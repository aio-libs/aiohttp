# aiohttp Threat Model

This document is a STRIDE-based threat model for the
[aiohttp](https://github.com/aio-libs/aiohttp) library. It is a living document
intended to (a) make explicit the implicit security assumptions baked into the
codebase, (b) catalogue known classes of threat against each subsystem, and
(c) record the existing and recommended mitigations.

---

## 1. Library Overview

**aiohttp** is an `asyncio`-based HTTP client/server framework for Python. It
provides:

- An **HTTP/1.1 server** (`aiohttp.web`) including routing, middleware,
  WebSocket support, static-file serving, and a Gunicorn worker.
- An **HTTP/1.1 client** (`aiohttp.ClientSession`) including connection
  pooling, TLS, proxy support, redirects, cookie handling, and WebSockets.
- Shared **wire-protocol code**: HTTP/1 parser (vendored
  [llhttp](https://github.com/nodejs/llhttp) wrapped in Cython, with a pure
  Python fallback), HTTP writer, WebSocket framing, multipart, and compression.

Key public APIs (non-exhaustive):

| Surface | Entry points |
| --- | --- |
| Server | `aiohttp.web.Application`, `web.RouteTableDef`, `web.run_app`, `web.AppRunner`, `web.WebSocketResponse`, `web.FileResponse` |
| Client | `aiohttp.ClientSession`, `aiohttp.TCPConnector`, `aiohttp.ClientResponse`, `aiohttp.WSMessage`, `aiohttp.BasicAuth` |
| Shared | `aiohttp.MultipartReader`/`MultipartWriter`, `aiohttp.CookieJar`, `aiohttp.TraceConfig`, `aiohttp.resolver.AsyncResolver` |

---

## 2. Methodology

We use [STRIDE](https://en.wikipedia.org/wiki/STRIDE_model):

- **S**poofing — impersonating identity (host, user, peer, dependency).
- **T**ampering — modifying data or code in flight or at rest.
- **R**epudiation — denying that an action occurred.
- **I**nformation Disclosure — leaking confidential data.
- **D**enial of Service — exhausting CPU, memory, sockets, file descriptors.
- **E**levation of Privilege — gaining unintended access.

Risk is ranked **High / Medium / Low** based on a rough product of likelihood
and impact, as judged by maintainers. Mitigations are split into
**existing** (already implemented in the codebase) and **recommended** (not
yet implemented or only partially implemented).

---

## 3. Overall Assets

These cross-cutting assets apply across most sections; individual sections only
list assets unique to that section.

1. **Integrity of public-API behavior** — functions return what callers expect
   and don't introduce protocol corruption (request smuggling, response
   splitting, framing desync).
2. **Confidentiality of data in transit** — TLS handling, header values,
   cookies, request/response bodies are not leaked between connections,
   sessions, or to log sinks.
3. **Availability of host application** — aiohttp does not crash, deadlock, or
   exhaust CPU/memory/FDs in the host process under hostile or malformed input.
4. **Security of host application** — aiohttp does not become a vector for
   attacks on the embedding application (SSRF, file disclosure, code execution,
   privilege escalation through deserialisation, etc.).
5. **Reputation & supply-chain integrity** — the released artifacts on PyPI are
   what maintainers built and signed; the source on GitHub matches the artifacts;
   the vendored llhttp matches upstream; CI/CD secrets are not exposed.

---

## 4. High-Level System Diagram

```mermaid
flowchart LR
  Untrusted([Untrusted Internet])
  Caller([Caller / host application])
  Upstream([External HTTP servers])

  subgraph Server[Server side]
    direction TB
    SP[web_protocol<br/>connection lifecycle]
    PARS[HTTP parser<br/>_http_parser.pyx + llhttp]
    REQ[web_request.Request]
    DISP[web_urldispatcher + middleware]
    HND{user handler}
    RESP[web_response.Response<br/>FileResponse / WebSocketResponse]
    WR[http_writer]
    SP --> PARS --> REQ --> DISP --> HND --> RESP --> WR
  end

  subgraph Client[Client side]
    direction TB
    CS[ClientSession]
    CONN[TCPConnector<br/>+ TLS, proxy, pooling]
    RES[resolver]
    CP[client_proto]
    CR[client_reqrep.ClientResponse]
    CS --> CONN --> RES
    CONN --> CP --> CR --> CS
  end

  subgraph Shared[Shared wire-protocol code]
    direction TB
    PARS
    WR
    WS[http_websocket + _websocket/]
    MP[multipart]
    COMP[compression_utils]
    PARS -.-> WS
    WR -.-> WS
  end

  Untrusted -- HTTP/1, WS --> SP
  WR -- HTTP/1, WS --> Untrusted

  Caller --> CS
  CS --> Caller
  CONN -- HTTP/1, WS --> Upstream
  Upstream --> CP

  CJ[(CookieJar)] -. client only .-> CS
  TR[TraceConfig] -. signals .-> CS
```

---

## 5. Scope

The threat surface is broken down into 19 sections. Each is modeled in its own
subsection below.

1. [HTTP/1 parser](#51-http1-parser)
2. [HTTP/1 writer](#52-http1-writer)
3. [WebSocket framing & per-message deflate](#53-websocket-framing--per-message-deflate)
4. [Multipart parsing & encoding](#54-multipart-parsing--encoding)
5. [Compression codecs](#55-compression-codecs)
6. [Streams & payloads](#56-streams--payloads)
7. [Server connection lifecycle](#57-server-connection-lifecycle)
8. [Server routing & middleware](#58-server-routing--middleware)
9. [Server request/response objects](#59-server-requestresponse-objects)
10. [Server static file serving](#510-server-static-file-serving)
11. [Server-side WebSocket handler](#511-server-side-websocket-handler)
12. [Client API & request lifecycle](#512-client-api--request-lifecycle)
13. [Connector / TLS / proxy / pooling](#513-connector--tls--proxy--pooling)
14. [Client-side WebSocket](#514-client-side-websocket)
15. [Client auth middlewares](#515-client-auth-middlewares)
16. [Cookie handling](#516-cookie-handling)
17. [DNS resolution](#517-dns-resolution)
18. [Tracing & URL/header helpers](#518-tracing--urlheader-helpers)
19. [Build & release supply chain](#519-build--release-supply-chain)

---

### 5.1. HTTP/1 parser

**Scope.** Parsing of HTTP/1.0 and HTTP/1.1 request and response messages —
request/status line, header block, chunked transfer-encoding, content-length
framing, trailers — and the surface where parsed values flow into the rest of
the library. Out of scope here: WebSocket framing ([§5.3](#53-websocket-framing--per-message-deflate)), multipart bodies
([§5.4](#54-multipart-parsing--encoding)), compression ([§5.5](#55-compression-codecs)), HTTP-writer-side framing ([§5.2](#52-http1-writer)).

**Components covered.**

- `aiohttp/_http_parser.pyx` — Cython wrapper over vendored llhttp, default in
  CPython builds.
- `aiohttp/_cparser.pxd` — Cython declarations for llhttp.
- `aiohttp/http_parser.py` — pure-Python `HttpRequestParser` / `HttpResponseParser`
  used as a fallback (and as the canonical implementation when
  `AIOHTTP_NO_EXTENSIONS=1`).
- `aiohttp/_find_header.pxd` / `aiohttp/_find_header.h` — header-name interning.
- `aiohttp/http_exceptions.py` — `BadHttpMessage`, `BadHttpMethod`,
  `BadStatusLine`, `LineTooLong`, `InvalidHeader`, `TransferEncodingError`,
  `ContentLengthError`.
- `vendor/llhttp/` — vendored upstream parser, version `9.3.1` (see
  `vendor/llhttp/package.json`). Generated via `make generate-llhttp`.

**Selection.** A conditional re-import at the bottom of
`aiohttp/http_parser.py` re-binds the public names to the Cython parser when
`_http_parser` imports successfully and `AIOHTTP_NO_EXTENSIONS` is unset. There is no hybrid mode — both request and
response parsers come from the same backend, so an inconsistent
request-Cython/response-pure-Python configuration cannot occur in supported
builds.

**Trust boundaries & data flow.**

```mermaid
flowchart LR
  Wire([Untrusted bytes]) --> Feed[parser.feed_data]
  Feed --> Llhttp[llhttp / Python state machine]
  Llhttp -->|RawRequestMessage<br/>RawResponseMessage| Caller[web_protocol / client_proto]
  Llhttp -->|StreamReader feed| Body[(Request/response body)]
  Caller --> ReqResp[Request / ClientResponse]
  ReqResp --> User([User handler / caller])
```

The parser is invoked on every byte that arrives from a socket, before any
authentication. **Everything fed into `feed_data` is attacker-controlled** on
the server side and **upstream-controlled** on the client side (proxies,
upstream services, malicious origins reached via client). The output
(`RawRequestMessage` / `RawResponseMessage`, raw header tuples, body chunks
into `StreamReader`) is then handed to `web_protocol.RequestHandler` and
`client_proto.ResponseHandler` respectively.

**Trust assumptions about parser output:**

- Header names are validated against a token regex; values are not normalised
  beyond `lstrip`/`rstrip` and CR/LF/NUL rejection.
- Header values are decoded `utf-8` with `surrogateescape`, so non-UTF-8 bytes
  are *preserved* and *can round-trip back to the wire* if downstream code
  re-emits them. Any sanitisation downstream of the parser is the
  responsibility of consumers (logging, header reflection, proxying).
- Methods are accepted as any RFC 7230 token; the parser does not canonicalise
  case.
- Versions are accepted by the regex `HTTP/(\d)\.(\d)` — i.e. `HTTP/0.9`,
  `HTTP/2.0`, etc. all parse without rejection, even though they cannot be
  served correctly.

**Assets at risk.**

- **Framing integrity** — that one wire message corresponds to one parsed
  message; nothing the parser accepts can cause a desync between aiohttp and
  an upstream/downstream peer (request smuggling).
- **Allocator safety** — that a malicious peer cannot drive memory or CPU
  usage to denial of service through parser-controlled allocations.
- **Bytewise transparency** — that bytes accepted by the parser cannot inject
  new framing or new header semantics downstream (CRLF injection, NUL
  smuggling).

**Threats (STRIDE).**

| # | Component / Vector | STRIDE | Threat | Risk |
| :--- | :--- | :--- | :--- | :--- |
| 1.1 | Request line / status line | T | Smuggling via duplicate / conflicting framing headers (`Content-Length` × N, `Content-Length` + `Transfer-Encoding`, obfuscated `Transfer-Encoding`). | High |
| 1.2 | Header block, line endings | T | Smuggling via bare-LF, obs-fold, optional CR-before-LF on the *request* parser. Request parser is strict; lenient flags apply only to the response parser. | Medium |
| 1.3 | Header values, CR/LF/NUL | T / I | CRLF injection enabling response splitting / header injection if downstream re-emits values verbatim. Historically [CVE-2023-37276](https://github.com/aio-libs/aiohttp/security/advisories/GHSA-45c4-8wx5-qw6w). | High |
| 1.4 | Header values, surrogateescape decode | I / T | Non-UTF-8 bytes round-trip through `Headers` and may be reflected by user code / proxies / logs into untrusted contexts. | Medium |
| 1.5 | HTTP version regex | T | `HTTP/0.9` and `HTTP/2.0` accepted on the wire, opening a small surface for protocol-confusion against intermediaries that handle these specially. | Low |
| 1.6 | Method token | I / T | Methods are not case-canonicalised; arbitrary tokens up to `max_line_size` accepted. May confuse downstream method-based authorisation if user code compares case-sensitively. | Low |
| 1.7 | `Content-Length` parsing | T | Negative or non-decimal CL handling, multiple comma-separated CLs, CL with leading `+`/whitespace. | Medium |
| 1.8 | `Transfer-Encoding: chunked` parsing | T | Lenient acceptance (`xchunked`, `chunked, identity`, doubled `chunked`) leading to smuggling against a non-aiohttp peer that interprets differently. | Medium |
| 1.9 | Chunk size parsing | D | No upper bound on chunk-size value (Python unbounded int); huge chunk size could drive allocator before `client_max_size` rejects body. Mitigated by [§5.7](#57-server-connection-lifecycle) / `client_max_size`. | Low–Med |
| 1.10 | Chunk extensions | D / T | Unbounded chunk-extension consumption per chunk; weak validation of extension syntax. | Low |
| 1.11 | Parser error reporting | I | Exception messages may include up to ~100 bytes of malformed input, which can be surfaced in 4xx error bodies, logs, or `DEBUG=True` traces. | Low |
| 1.12 | Cython ⇄ pure-Python divergence | T / S | Behaviour differences between llhttp and the Python fallback may produce parser-confusion if a deployment unintentionally switches backends (e.g. a user installs without compiled extensions). | Med |
| 1.13 | Vendored llhttp version drift | S / T | An upstream llhttp CVE not picked up by aiohttp's vendoring cadence remains exploitable until `make generate-llhttp` is re-run and released. | Medium |
| 1.14 | Build/regen of llhttp (`make generate-llhttp`) | S / T | Local tampering or supply-chain compromise of the npm `llhttp` package gets baked into the vendored C. Covered in [§5.19](#519-build--release-supply-chain) but originates here. | Medium |

**Mitigations.**

| # | Threat | Existing | Recommended |
| :--- | :--- | :--- | :--- |
| 1.1 | Smuggling via duplicate framing headers | llhttp rejects conflicting `Content-Length`. `http_parser.py:HttpRequestParserPy.parse_headers` rejects coexistence of CL + `Transfer-Encoding: chunked`. The full `SINGLETON_HEADERS` set (CL, CT, Host, TE, ETag, etc.) is duplicate-rejected by the request parser (strict mode); `#12302` disabled this check on the response parser (lax mode), since real-world servers commonly send duplicate `Content-Type` / `Server`. | If new singleton-sensitive headers emerge in HTTP/1.1 RFC errata, add to `SINGLETON_HEADERS`. |
| 1.2 | Lenient response parsing | Lenient flags (`llhttp_set_lenient_headers`, `llhttp_set_lenient_optional_cr_before_lf`, `llhttp_set_lenient_spaces_after_chunk_size`) are only enabled on the **response** parser and only when `DEBUG` is False (set in `HttpResponseParser.__init__`). The **request** parser is strict. | Documented design decision: keep lenient response parsing for real-world server interop |
| 1.3 | CRLF / NUL in header values | Bytes `\r`, `\n`, `\x00` rejected in header values (`_http_parser.pyx` callbacks; `http_parser.py:HeadersParser.parse_headers`). | Keep regression tests in `tests/test_http_parser.py` covering each forbidden byte both in name and value, and across both Cython and pure-Python parsers. |
| 1.4 | Non-UTF-8 round-trip | None at parser layer (intentional — preserving original bytes is required for some use cases). | **Document in user-facing docs that header values are bytes-preserving; warn against reflecting headers verbatim into responses, logs, or sub-requests without re-validation.** |
| 1.5 | HTTP version regex accepts 0.9 / 2.0 | None (regex is permissive). | **Tighten `VERSRE` (and llhttp configuration if possible) to reject anything outside `HTTP/1.0` and `HTTP/1.1`.** |
| 1.6 | Method-case round-trip | Method token validated by regex; not canonicalised. | **Document that user route handlers / authorization checks should compare methods case-sensitively to the canonical RFC tokens, or use the framework's `web.RouteTableDef` decorators which already match canonical methods.** |
| 1.7 | `Content-Length` parsing | llhttp validates CL is decimal and non-negative; pure-Python parser validates via `DIGITS.fullmatch(r"\d+")` before `int(...)`, rejecting `+`/`-`/non-ASCII-digit forms (`test_bad_headers`, `test_headers_content_length_err_*` cover these). | None. Cross-backend parity is covered by the shared parser tests. |
| 1.8 | `Transfer-Encoding` lenience | `_is_chunked_te` requires `chunked` to be the last value; duplicate `chunked` rejected (`#10611`). Request parser strict. | None. |
| 1.9 | Chunk-size DoS | The parser doesn't cap chunk size, but **server-side body length is bounded by `client_max_size` (default `1 MiB`)** in `web_request.py:BaseRequest.read`. Client-side responses are bounded by user-supplied `max_body_size` / streaming reads. | None. If a cap is ever needed at the parser level, plumb it through `HttpPayloadParser`. |
| 1.10 | Chunk-extension DoS | Chunk-extension content is bounded by the same wire-level size constraints (it shares the chunk-size line with `max_line_size`). | **Add an explicit test that chunk-extension flooding cannot blow past `max_line_size`.** |
| 1.11 | Parser error reflection | `http_parser.py` truncates to `[:100]` for line errors. Server-side error path renders 4xx with the exception message; tracebacks only when `DEBUG=True`. | **Audit any path where `BadHttpMessage` content is reflected to the client unsanitised (especially in custom `web_log` configurations).** |
| 1.12 | Cython ⇄ pure-Python divergence | `tests/test_http_parser.py` parameterises tests over `REQUEST_PARSERS` / `RESPONSE_PARSERS` (pure-Python always; Cython when the extension imports). The high-leverage attack vectors are already covered under both backends: CL+TE (`test_content_length_transfer_encoding`), CL×N (`test_duplicate_singleton_header_rejected`), obs-fold (`test_reject_obsolete_line_folding`, `test_http_response_parser_obs_line_folding*`), CR/LF/NUL (`test_bad_headers`, `test_http_response_parser_null_byte_in_header_value`, `test_http_response_parser_bad_crlf`), version regex (`test_http_request_parser_bad_version*`, `test_http_response_parser_bad_version*`). | None. When new attack vectors emerge, add them to the parameterised tests. |
| 1.13 | llhttp version drift | Manual upgrade via `make generate-llhttp`; vendor pinned in `vendor/llhttp/package.json`. | Track upstream releases (e.g. via Dependabot rule for `vendor/llhttp/package.json`), bump on every llhttp release, regenerate in CI. |
| 1.14 | npm-side compromise of `llhttp` | The vendored output is checked into git, so a compromise during a future regen would be detectable in PR review. See [§5.19](#519-build--release-supply-chain). | **Make the llhttp build reproducible: pin Node.js version, commit the npm lockfile, and on every bump verify the regenerated C against upstream's release tarballs before committing.** |

**Past advisories / hardening (recap).**

- **GHSA-xx9p-xxvh-7g8j (CVE-2023-47641)** (3.8.0) — CL-vs-TE divergence
  between the Cython and pure-Python parsers, allowing request smuggling
  against deployments that switched backends.
- **CVE-2023-37276 / GHSA-45c4-8wx5-qw6w** (3.8.5) — HTTP request smuggling
  via CR/LF/NUL in header values. Both parsers reject these bytes at the
  byte level.
- **GHSA-pjjw-qhg8-p2p9** (3.8.6) — smuggling pair in vendored llhttp 8.1.1;
  fixed by bumping llhttp to 9.
- **GHSA-gfw2-4jvh-wgfg / GHSA-8qpw-xqxj-h4r2** (3.8.6 / 3.9.2) — pure-Python
  parser accepted lenient separators / weak RFC validation that llhttp
  rejected.
- **GHSA-8495-4g3g-x7pr (CVE-2024-52304)** (3.10.11) — chunk-extension
  newline smuggling in the pure-Python parser.
- **GHSA-9548-qrrj-x5pj (CVE-2025-53643)** (3.12.14) — request smuggling
  via the chunked-trailer section in the pure-Python parser.
- **GHSA-69f9-5gxw-wvc2 (CVE-2025-69224)** (3.13.3) — Unicode codepoints
  matched by `\d` in the pure-Python parser's regexes were treated as
  digits.
- **GHSA-g84x-mcqj-x9qq** (3.13.3) — CPU-DoS on `request.read()` when
  the body arrives as a very large number of small chunks.
- **PR #12137** (3.13.4) — precautionary hardening: pure-Python parser
  now explicitly rejects duplicate `Transfer-Encoding: chunked` on
  the request parser.
- **GHSA-c427-h43c-vf67** (3.13.4) — duplicate `Host` header accepted
  in request parser, bypassing `Application.add_domain()` host-based
  routing / authorisation. Fixed by adding `Host` to the strict
  request-parser singleton rejection set.
- **GHSA-63hf-3vf5-4wqf (CVE-2026-34520)** (3.13.4) — llhttp accepted
  NUL / control bytes in *response* header values, leaving the response
  parser weaker than the request parser. Fixed by tightening the
  response-side byte check.
- **GHSA-w2fm-2cpv-w7v5 (CVE-2026-22815)** (3.13.4) — uncapped memory
  growth on long header / trailer blocks. Fixed by enforcing
  `max_field_size` / `max_headers` on the trailer block too.
- **PR #12302** (3.13.5) — duplicate-singleton-header rejection
  was breaking real-world response parsing (servers like Google APIs /
  Werkzeug emit duplicate `Content-Type` / `Server`); fix disables the
  check on the response parser (lax mode) while keeping it on the
  request parser (strict).

These are all currently in place; this section assumes no regression.

---
