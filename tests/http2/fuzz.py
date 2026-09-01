import asyncio
import random
import struct
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union, cast

from http2.utils import (
    build_data_frame,
    build_goaway,
    build_headers_frame,
    build_ping,
    build_rst_stream,
    build_settings_frame,
    build_window_update,
    frame_header,
)

from aiohttp.http2.connection import Http2Connection
from aiohttp.http2.errors import ErrorCode, ProtocolError
from aiohttp.http2.settings import DEFAULT_SETTINGS, FrameType, Setting
from aiohttp.http2.stream import StreamState


# ----------------------------------------------------------------------
# Server state representation
# ----------------------------------------------------------------------
@dataclass
class ServerStreamState:
    """State of a single stream from the server's perspective."""

    stream_id: int
    state: str = "idle"
    recv_window: int = 65535
    send_window: int = 65535
    pending_data: int = 0


@dataclass
class ServerConnectionState:
    """Full HTTP/2 connection state as seen by the server."""

    streams: Dict[int, ServerStreamState] = field(default_factory=dict)
    last_stream_id: int = 0
    settings: Dict[Setting, int] = field(
        default_factory=lambda: DEFAULT_SETTINGS.copy()
    )
    peer_settings: Dict[Setting, int] = field(
        default_factory=dict
    )  # settings received from client
    goaway_sent: bool = False
    goaway_received: bool = False

    def get_stream(self, stream_id: int) -> ServerStreamState:
        if stream_id not in self.streams:
            self.streams[stream_id] = ServerStreamState(stream_id=stream_id)
        return self.streams[stream_id]


# ----------------------------------------------------------------------
# Fuzzer configuration
# ----------------------------------------------------------------------
@dataclass
class FuzzerConfig:
    """Probability distributions for frame generation.

    Each field is a dict mapping a choice to a weight (or a single value).
    For example, frame_type_probs = {FrameType.HEADERS: 30, FrameType.DATA: 20, ...}
    The fuzzer will randomly choose according to these weights.
    """

    frame_type_probs: Dict[int, int] = field(
        default_factory=lambda: {
            FrameType.HEADERS: 30,
            FrameType.DATA: 25,
            FrameType.SETTINGS: 10,
            FrameType.RST_STREAM: 10,
            FrameType.WINDOW_UPDATE: 10,
            FrameType.PING: 10,
            FrameType.GOAWAY: 5,
        }
    )
    # Probabilities for flags on HEADERS frames
    headers_end_stream_prob: float = 0.3
    headers_end_headers_prob: float = 0.9
    headers_priority_prob: float = 0.1
    # DATA frame flags
    data_end_stream_prob: float = 0.4
    data_padded_prob: float = 0.2
    # Probability that a stream ID is invalid (e.g., 0 or even)
    invalid_stream_id_prob: float = 0.1
    # Probability to violate protocol deliberately (e.g., send DATA on closed stream)
    violate_protocol_prob: float = 0.2
    # Maximum number of frames to send in one cycle
    max_frames_per_cycle: int = 3
    # Random seed (optional)
    seed: Optional[int] = None


# ----------------------------------------------------------------------
# Main fuzzer class
# ----------------------------------------------------------------------
class Http2ServerFuzzer:
    """Stateful fuzzer that acts as an HTTP/2 server and sends arbitrary frames
    to an aiohttp client connection.

    Parameters
    ----------
    connection : Http2Connection
        The client under test.
    transport : MagicMock
        Mock transport used by the connection; its write method will be
        recorded to capture client frames.
    config : FuzzerConfig
        Probability distributions for frame generation.
    max_cycles : int
        Number of fuzzing cycles to run.
    verification : Callable
        Function that receives ``(sent_frames, client_frames, state)`` and
        returns ``True`` if no bug was found, ``False`` if a bug occurred.
        It can also raise an AssertionError to indicate a bug with a message.
    """

    def __init__(
        self,
        connection: Http2Connection,
        transport: Any,
        config: FuzzerConfig = FuzzerConfig(),
        max_cycles: int = 100,
        verification: Optional[
            Callable[
                [List[bytes], List[Tuple[int, int, int, bytes]], ServerConnectionState],
                bool,
            ]
        ] = None,
    ):
        self.connection = connection
        self.transport = transport
        self.config = config
        self.max_cycles = max_cycles
        self.verification = verification or self.default_verification

        self.state = ServerConnectionState()
        self.rng = random.Random(config.seed)

        # Keep track of client frames sent via transport.write
        self.client_frame_buffer: List[bytes] = []
        self._record_client_frames()

    def _record_client_frames(self) -> None:
        """Patch transport.write to collect outgoing client frames."""
        original_write = self.transport.write

        def write_and_record(data: bytes) -> None:
            self.client_frame_buffer.append(data)
            original_write(data)

        self.transport.write = write_and_record

    def _clear_client_frames(self) -> None:
        self.client_frame_buffer.clear()

    def _parse_client_frames(self, data: bytes) -> List[Tuple[int, int, int, bytes]]:
        """Parse raw bytes into a list of (length, type, flags, payload)."""
        frames = []
        while len(data) >= 9:
            length = int.from_bytes(data[:3], "big")
            ftype = data[3]
            flags = data[4]
            stream_id = int.from_bytes(data[5:9], "big") & 0x7FFFFFFF
            if len(data) < 9 + length:
                break  # incomplete frame
            payload = data[9 : 9 + length]
            frames.append((length, ftype, flags, payload))
            data = data[9 + length :]
        return frames

    def _get_client_frames_since_last_cycle(self) -> List[Tuple[int, int, int, bytes]]:
        """Extract and parse all client frames written since last clear."""
        all_raw = b"".join(self.client_frame_buffer)
        self._clear_client_frames()
        return self._parse_client_frames(all_raw)

    # ------------------------------------------------------------------
    # State update helpers (server perspective)
    # ------------------------------------------------------------------
    def _apply_client_frames_to_state(
        self, frames: List[Tuple[int, int, int, bytes]]
    ) -> None:
        """Update server state based on what the client sent."""
        for length, ftype, flags, payload in frames:
            if ftype == FrameType.SETTINGS:
                # parse settings payload (each setting is 6 bytes: id, value)
                if not (flags & 0x1):  # not ACK
                    for i in range(0, len(payload), 6):
                        setting_id = int.from_bytes(payload[i : i + 2], "big")
                        value = int.from_bytes(payload[i + 2 : i + 6], "big")
                        # Convert to Setting enum, ignore unknown ids
                        try:
                            setting: Setting = Setting(setting_id)
                        except ValueError:
                            continue
                        self.state.peer_settings[setting] = value
            elif ftype == FrameType.HEADERS:
                pass
            elif ftype == FrameType.RST_STREAM:
                stream_id = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
                if stream_id in self.state.streams:
                    self.state.streams[stream_id].state = "closed"
            elif ftype == FrameType.WINDOW_UPDATE:
                stream_id = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
                increment = int.from_bytes(payload[4:8], "big")
                if stream_id == 0:
                    # connection-level window update
                    pass
                else:
                    stream = self.state.get_stream(stream_id)
                    stream.send_window += increment
            elif ftype == FrameType.GOAWAY:
                self.state.goaway_received = True

    # ------------------------------------------------------------------
    # Frame generation (server ->  client)
    # ------------------------------------------------------------------
    def _choose_frame_type(self) -> int:
        types = list(self.config.frame_type_probs.keys())
        weights = list(self.config.frame_type_probs.values())
        return self.rng.choices(types, weights=weights, k=1)[0]

    def _generate_frame(self) -> bytes:
        """Generate a single frame based on current state and probabilities."""
        ftype = self._choose_frame_type()
        # Determine stream ID (0 for connection-level frames, random valid/invalid otherwise)
        use_invalid_stream = self.rng.random() < self.config.invalid_stream_id_prob
        if ftype in {FrameType.SETTINGS, FrameType.PING, FrameType.GOAWAY}:
            stream_id = 0
        else:
            # Choose from existing streams or create a new one
            stream_ids = [
                s for s in self.state.streams.keys() if s % 2 == 1
            ]  # client-initiated odd streams
            if stream_ids and self.rng.random() < 0.7:
                stream_id = self.rng.choice(stream_ids)
            else:
                # new stream ID (odd, greater than last used)
                stream_id = (
                    max([0] + [s for s in self.state.streams.keys() if s % 2 == 1]) + 2
                )
                if use_invalid_stream:
                    # make it even or 0 to test error handling
                    stream_id = self.rng.choice([0, stream_id - 1])
                self.state.get_stream(stream_id)  # ensure exists

        if ftype == FrameType.SETTINGS:
            # Random settings (maybe invalid values)
            settings_pairs = []
            for _ in range(self.rng.randint(0, 3)):
                setting = self.rng.choice(list(Setting))
                value = self.rng.randint(0, 2**32 - 1)
                settings_pairs.append((setting, value))
            ack = self.rng.random() < 0.2
            frame = build_settings_frame(settings_pairs, ack=ack)

        elif ftype == FrameType.HEADERS:
            # Generate response headers
            headers = [
                (":status", str(self.rng.choice([200, 204, 400, 500]))),
                ("content-type", "text/plain"),
                (
                    "x-fuzz",
                    "".join(self.rng.choices("abcdef", k=self.rng.randint(0, 20))),
                ),
            ]
            end_stream = self.rng.random() < self.config.headers_end_stream_prob
            end_headers = self.rng.random() < self.config.headers_end_headers_prob
            priority = None
            if self.rng.random() < self.config.headers_priority_prob:
                priority = b"\x00" * 5  # dummy priority
            frame = build_headers_frame(
                stream_id,
                headers,
                end_headers=end_headers,
                end_stream=end_stream,
                priority=priority,
            )

        elif ftype == FrameType.DATA:
            data_len = self.rng.randint(0, self.state.settings[Setting.MAX_FRAME_SIZE])
            data = bytes(self.rng.getrandbits(8) for _ in range(data_len))
            end_stream = self.rng.random() < self.config.data_end_stream_prob
            padded = self.rng.random() < self.config.data_padded_prob
            frame = build_data_frame(stream_id, data, end_stream=end_stream, pad=padded)

        elif ftype == FrameType.RST_STREAM:
            error_code = self.rng.choice(list(ErrorCode)).value
            frame = build_rst_stream(stream_id, error_code)

        elif ftype == FrameType.WINDOW_UPDATE:
            increment = self.rng.randint(1, 2**31 - 1)
            frame = build_window_update(stream_id, increment)

        elif ftype == FrameType.PING:
            ack = self.rng.random() < 0.5
            opaque = bytes(self.rng.getrandbits(8) for _ in range(8))
            frame = build_ping(ack=ack, opaque=opaque)

        elif ftype == FrameType.GOAWAY:
            last_stream_id = self.rng.choice([0, stream_id])
            error_code = self.rng.choice(list(ErrorCode)).value
            extra = b"fuzz"
            frame = build_goaway(last_stream_id, error_code, extra)
            self.state.goaway_sent = True

        else:
            frame = b""  # unsupported for now

        # Update server state based on the frame we are about to send
        self._apply_sent_frame_to_state(ftype, stream_id, frame)
        return frame

    def _apply_sent_frame_to_state(
        self, ftype: int, stream_id: int, frame: bytes
    ) -> None:
        """Update server state after sending a frame."""
        if ftype == FrameType.HEADERS:
            stream = self.state.get_stream(stream_id)
            # If END_STREAM flag set, stream becomes half-closed (local)
            if frame[4] & 0x1:  # END_STREAM flag
                stream.state = "half_closed_local"
            else:
                stream.state = "open"
        elif ftype == FrameType.DATA:
            stream = self.state.get_stream(stream_id)
            if frame[4] & 0x1:
                stream.state = "half_closed_local"
            # Reduce send window
            payload_len = len(frame) - 9
            stream.send_window -= payload_len
        elif ftype == FrameType.RST_STREAM:
            self.state.get_stream(stream_id).state = "closed"
        elif ftype == FrameType.GOAWAY:
            self.state.goaway_sent = True

    # ------------------------------------------------------------------
    # Main fuzzing loop
    # ------------------------------------------------------------------
    def run(self) -> List[Dict[str, Any]]:
        """Run the fuzzer for max_cycles cycles.

        Returns a list of bug reports (empty if no bugs found).
        """
        bugs = []
        for cycle in range(self.max_cycles):
            # Step 1: Get client frames sent since last cycle
            client_frames = self._get_client_frames_since_last_cycle()
            self._apply_client_frames_to_state(client_frames)

            # Step 2: Generate one or more server frames
            num_frames = self.rng.randint(1, self.config.max_frames_per_cycle)
            sent_frames = []
            for _ in range(num_frames):
                frame = self._generate_frame()
                sent_frames.append(frame)
                # Feed each frame to the client immediately
                self.connection.data_received(frame)
                # Check for immediate client reaction (e.g., exceptions)
                # The client may write frames during data_received
                # We'll capture them in the next iteration, but we can also
                # check for exceptions here.

            # Step 3: Collect client frames produced as a reaction
            reaction_frames = self._get_client_frames_since_last_cycle()
            self._apply_client_frames_to_state(reaction_frames)

            # Step 4: Verify
            try:
                is_bug = not self.verification(sent_frames, reaction_frames, self.state)
            except AssertionError as e:
                is_bug = True
                bug_info = str(e)
            else:
                bug_info = "Verification returned False"

            if is_bug:
                bugs.append(
                    {
                        "cycle": cycle,
                        "sent_frames": sent_frames,
                        "client_frames": reaction_frames,
                        "state": self.state,
                        "info": bug_info,
                    }
                )
        return bugs

    # ------------------------------------------------------------------
    # Default verification (override or replace)
    # ------------------------------------------------------------------
    def default_verification(
        self,
        sent_frames: List[bytes],
        client_frames: List[Tuple[int, int, int, bytes]],
        state: ServerConnectionState,
    ) -> bool:
        """Basic sanity checks:
        - Client must not crash (obviously handled by test harness)
        - If we send a GOAWAY, client should eventually close connection.
        - If we send RST_STREAM on a stream, client should not send DATA on that stream.
        - If we violate a protocol rule, client should send an error (RST_STREAM/GOAWAY).
        """
        # We only check the client didn't send data to a closed stream
        for _, ftype, _, payload in client_frames:
            if ftype == FrameType.DATA:
                stream_id = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
                if (
                    stream_id in state.streams
                    and state.streams[stream_id].state == "closed"
                ):
                    return False
        return True
