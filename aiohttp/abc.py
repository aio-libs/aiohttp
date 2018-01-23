import asyncio
from abc import ABC, abstractmethod
from collections.abc import Iterable, Sized


class AbstractRouter(ABC):

    def __init__(self):
        self._frozen = False

    def post_init(self, app):
        """Post init stage.

        Not an abstract method for sake of backward compatibility,
        but if the router wants to be aware of the application
        it can override this.
        """

    @property
    def frozen(self):
        return self._frozen

    def freeze(self):
        """Freeze router."""
        self._frozen = True

    @abstractmethod
    async def resolve(self, request):
        """Return MATCH_INFO for given request"""


class AbstractMatchInfo(ABC):

    @abstractmethod
    async def handler(self, request):
        """Execute matched request handler"""

    @abstractmethod
    async def expect_handler(self, request):
        """Expect handler for 100-continue processing"""

    @property  # pragma: no branch
    @abstractmethod
    def http_exception(self):
        """HTTPException instance raised on router's resolving, or None"""

    @abstractmethod  # pragma: no branch
    def get_info(self):
        """Return a dict with additional info useful for introspection"""

    @property  # pragma: no branch
    @abstractmethod
    def apps(self):
        """Stack of nested applications.

        Top level application is left-most element.

        """

    @abstractmethod
    def add_app(self, app):
        """Add application to the nested apps stack."""

    @abstractmethod
    def freeze(self):
        """Freeze the match info.

        The method is called after route resolution.

        After the call .add_app() is forbidden.

        """


class AbstractView(ABC):
    """Abstract class based view."""

    def __init__(self, request):
        self._request = request

    @property
    def request(self):
        """Request instance."""
        return self._request

    @abstractmethod
    def __await__(self):
        """Execute the view handler."""


class AbstractResolver(ABC):
    """Abstract DNS resolver."""

    @abstractmethod
    async def resolve(self, hostname):
        """Return IP address for given hostname"""

    @abstractmethod
    async def close(self):
        """Release resolver"""


class AbstractCookieJar(Sized, Iterable):
    """Abstract Cookie Jar."""

    def __init__(self, *, loop=None):
        self._loop = loop or asyncio.get_event_loop()

    @abstractmethod
    def clear(self):
        """Clear all cookies."""

    @abstractmethod
    def update_cookies(self, cookies, response_url=None):
        """Update cookies."""

    @abstractmethod
    def filter_cookies(self, request_url):
        """Return the jar's cookies filtered by their attributes."""


class AbstractStreamWriter(ABC):
    """Abstract stream writer."""

    @abstractmethod
    async def write(self, chunk):
        """Write chunk into stream."""

    @abstractmethod
    async def write_eof(self, chunk=b''):
        """Write last chunk."""

    @abstractmethod
    async def drain(self):
        """Flush the write buffer."""


class AbstractAccessLogger(ABC):
    """Abstract writer to access log."""

    def __init__(self, logger, log_format):
        self.logger = logger
        self.log_format = log_format

    @abstractmethod
    def log(self, request, response, time):
        """Emit log to logger."""
