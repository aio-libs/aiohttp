import datetime
import re
from collections import defaultdict
from collections.abc import Mapping
from http.cookies import Morsel, SimpleCookie
from math import ceil
from urllib.parse import urlsplit

from .abc import AbstractCookieJar
from .helpers import is_ip_address


class CookieJar(AbstractCookieJar):
    """Implements cookie storage adhering to RFC 6265."""

    DATE_TOKENS_RE = re.compile(
        "[\x09\x20-\x2F\x3B-\x40\x5B-\x60\x7B-\x7E]*"
        "(?P<token>[\x00-\x08\x0A-\x1F\d:a-zA-Z\x7F-\xFF]+)")

    DATE_HMS_TIME_RE = re.compile("(\d{1,2}):(\d{1,2}):(\d{1,2})")

    DATE_DAY_OF_MONTH_RE = re.compile("(\d{1,2})")

    DATE_MONTH_RE = re.compile(
        "(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)", re.I)

    DATE_YEAR_RE = re.compile("(\d{2,4})")

    MAX_TIME = 2208985261.0  # so far in future (1/1/2100)

    def __init__(self, *, unsafe=False, loop=None):
        super().__init__(loop=loop)
        self._cookies = defaultdict(SimpleCookie)
        self._host_only_cookies = set()
        self._unsafe = unsafe
        self._next_expiration = ceil(loop.time())
        self._expirations = {}

    def clear(self):
        self._cookies.clear()
        self._host_only_cookies.clear()
        self._next_expiration = ceil(self._loop.time())
        self._expirations.clear()

    def __iter__(self):
        self._do_expiration()
        for val in self._cookies.values():
            yield from val.values()

    def __len__(self):
        return sum(1 for i in self)

    def _do_expiration(self):
        now = self._loop.time()
        if self._next_expiration > now:
            return
        if not self._expirations:
            return
        next_expiration = self.MAX_TIME
        to_del = []
        cookies = self._cookies
        expirations = self._expirations
        for (domain, name), when in expirations.items():
            if when < now:
                cookies[domain].pop(name, None)
                to_del.append((domain, name))
                self._host_only_cookies.discard((domain, name))
            else:
                next_expiration = min(next_expiration, when)
        for key in to_del:
            del expirations[key]

        self._next_expiration = ceil(next_expiration)

    def _expire_cookie(self, when, domain, name):
        self._next_expiration = min(self._next_expiration, when)
        self._expirations[(domain, name)] = when

    def update_cookies(self, cookies, response_url=None):
        """Update cookies."""
        url_parsed = urlsplit(response_url or "")
        hostname = url_parsed.hostname

        if not self._unsafe and is_ip_address(hostname):
            # Don't accept cookies from IPs
            return

        if isinstance(cookies, Mapping):
            cookies = cookies.items()

        for name, cookie in cookies:
            if not isinstance(cookie, Morsel):
                tmp = SimpleCookie()
                tmp[name] = cookie
                cookie = tmp[name]

            domain = cookie["domain"]

            # ignore domains with trailing dots
            if domain.endswith('.'):
                domain = ""
                del cookie["domain"]

            if not domain and hostname is not None:
                # Set the cookie's domain to the response hostname
                # and set its host-only-flag
                self._host_only_cookies.add((hostname, name))
                domain = cookie["domain"] = hostname

            if domain.startswith("."):
                # Remove leading dot
                domain = domain[1:]
                cookie["domain"] = domain

            if hostname and not self._is_domain_match(domain, hostname):
                # Setting cookies for different domains is not allowed
                continue

            path = cookie["path"]
            if not path or not path.startswith("/"):
                # Set the cookie's path to the response path
                path = url_parsed.path
                if not path.startswith("/"):
                    path = "/"
                else:
                    # Cut everything from the last slash to the end
                    path = "/" + path[1:path.rfind("/")]
                cookie["path"] = path

            max_age = cookie["max-age"]
            if max_age:
                try:
                    delta_seconds = int(max_age)
                    self._expire_cookie(self._loop.time() + delta_seconds,
                                        domain, name)
                except ValueError:
                    cookie["max-age"] = ""

            else:
                expires = cookie["expires"]
                if expires:
                    expire_time = self._parse_date(expires)
                    if expire_time:
                        self._expire_cookie(expire_time.timestamp(),
                                            domain, name)
                    else:
                        cookie["expires"] = ""

            # use dict method because SimpleCookie class modifies value
            # before Python 3.4.3
            dict.__setitem__(self._cookies[domain], name, cookie)

        self._do_expiration()

    def filter_cookies(self, request_url):
        """Returns this jar's cookies filtered by their attributes."""
        self._do_expiration()
        url_parsed = urlsplit(request_url)
        filtered = SimpleCookie()
        hostname = url_parsed.hostname or ""
        is_not_secure = url_parsed.scheme not in ("https", "wss")

        for cookie in self:
            name = cookie.key
            domain = cookie["domain"]

            # Send shared cookies
            if not domain:
                filtered[name] = cookie.value
                continue

            if not self._unsafe and is_ip_address(hostname):
                continue

            if (domain, name) in self._host_only_cookies:
                if domain != hostname:
                    continue
            elif not self._is_domain_match(domain, hostname):
                continue

            if not self._is_path_match(url_parsed.path, cookie["path"]):
                continue

            if is_not_secure and cookie["secure"]:
                continue

            filtered[name] = cookie.value

        return filtered

    @staticmethod
    def _is_domain_match(domain, hostname):
        """Implements domain matching adhering to RFC 6265."""
        if hostname == domain:
            return True

        if not hostname.endswith(domain):
            return False

        non_matching = hostname[:-len(domain)]

        if not non_matching.endswith("."):
            return False

        return not is_ip_address(hostname)

    @staticmethod
    def _is_path_match(req_path, cookie_path):
        """Implements path matching adhering to RFC 6265."""
        if not req_path.startswith("/"):
            req_path = "/"

        if req_path == cookie_path:
            return True

        if not req_path.startswith(cookie_path):
            return False

        if cookie_path.endswith("/"):
            return True

        non_matching = req_path[len(cookie_path):]

        return non_matching.startswith("/")

    @classmethod
    def _parse_date(cls, date_str):
        """Implements date string parsing adhering to RFC 6265."""
        if not date_str:
            return

        found_time = False
        found_day_of_month = False
        found_month = False
        found_year = False

        hour = minute = second = 0
        day_of_month = 0
        month = ""
        year = 0

        for token_match in cls.DATE_TOKENS_RE.finditer(date_str):

            token = token_match.group("token")

            if not found_time:
                time_match = cls.DATE_HMS_TIME_RE.match(token)
                if time_match:
                    found_time = True
                    hour, minute, second = [
                        int(s) for s in time_match.groups()]
                    continue

            if not found_day_of_month:
                day_of_month_match = cls.DATE_DAY_OF_MONTH_RE.match(token)
                if day_of_month_match:
                    found_day_of_month = True
                    day_of_month = int(day_of_month_match.group())
                    continue

            if not found_month:
                month_match = cls.DATE_MONTH_RE.match(token)
                if month_match:
                    found_month = True
                    month = month_match.group()
                    continue

            if not found_year:
                year_match = cls.DATE_YEAR_RE.match(token)
                if year_match:
                    found_year = True
                    year = int(year_match.group())

        if 70 <= year <= 99:
            year += 1900
        elif 0 <= year <= 69:
            year += 2000

        if False in (found_day_of_month, found_month, found_year, found_time):
            return

        if not 1 <= day_of_month <= 31:
            return

        if year < 1601 or hour > 23 or minute > 59 or second > 59:
            return

        dt = datetime.datetime.strptime(
            "%s %d %d:%d:%d %d" % (
                month, day_of_month, hour, minute, second, year
            ), "%b %d %H:%M:%S %Y")

        return dt.replace(tzinfo=datetime.timezone.utc)
