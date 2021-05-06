import re
from typing import Optional, Set
import urllib.parse

from ..i18n import _

## The following code (albeit modified) is from the given URL and their license applies.
##   https://stackoverflow.com/a/55827638


class UrlValidationError(Exception):
    NO_URL_SPECIFIED = 1
    URL_TOO_LONG = 2
    ONLY_HOST_WANTED = 3
    NO_SCHEME_SPECIFIED = 4
    INVALID_SCHEME = 5
    NO_DOMAIN_SPECIFIED = 6
    INVALID_DOMAIN = 7

    """
    In an ideal world we could pass in the localised error message as the exception reason and
    do away with this class, but in this one we want the ability to programmatically distinguish
    between errors and the localised messages would not give us that. So instead an error is
    classed by a code and the localised message is implicitly matched and used.
    """
    def __init__(self, code: int) -> None:
        self.code = code
        message = URL_VALIDATION_MESSAGES.get(code, _("Internal error"))
        super().__init__(message)


URL_VALIDATION_MESSAGES = {
    UrlValidationError.NO_URL_SPECIFIED: _("No URL specified"),
    UrlValidationError.URL_TOO_LONG: _("Too long"),
    UrlValidationError.ONLY_HOST_WANTED: _("Excess information beyond host and scheme"),
    UrlValidationError.NO_SCHEME_SPECIFIED: _("Scheme not found"),
    UrlValidationError.INVALID_SCHEME: _("Invalid scheme"),
    UrlValidationError.NO_DOMAIN_SPECIFIED: _("Host not found"),
    UrlValidationError.INVALID_DOMAIN: _("Invalid host"),
}


# Check https://regex101.com/r/A326u1/5 for reference
DOMAIN_FORMAT = re.compile(
    # http basic authentication [optional]
    r"(?:^(\w{1,255}):(.{1,255})@|^)"
    # check full domain length to be less than or equal to 253 (starting after http basic auth,
    # stopping before port)
    r"(?:(?:(?=\S{0,253}(?:$|:))"
    # check for at least one subdomain (maximum length per subdomain: 63 characters), dashes
    # in between allowed
    r"((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    # check for top level domain, no dashes allowed
    r"(?:[a-z0-9]{1,63})))"
    # accept also "localhost" only
    r"|localhost)"
    # port [optional]
    r"(:\d{1,5})?",
    re.IGNORECASE
)
DEFAULT_SCHEMES = { "http", "https" }

def validate_url(url: str, schemes: Optional[Set[str]]=None, host_only: bool=False) -> str:
    if schemes is None:
        schemes = DEFAULT_SCHEMES

    url = url.strip()

    if not url:
        raise UrlValidationError(UrlValidationError.NO_URL_SPECIFIED)

    if len(url) > 2048:
        raise UrlValidationError(UrlValidationError.URL_TOO_LONG)

    result = urllib.parse.urlparse(url)

    scheme = result.scheme
    domain = result.netloc

    if not scheme:
        raise UrlValidationError(UrlValidationError.NO_SCHEME_SPECIFIED)

    if scheme.lower() not in schemes:
        raise UrlValidationError(UrlValidationError.INVALID_SCHEME)

    if not domain:
        raise UrlValidationError(UrlValidationError.NO_DOMAIN_SPECIFIED)

    if not re.fullmatch(DOMAIN_FORMAT, domain):
        raise UrlValidationError(UrlValidationError.INVALID_DOMAIN)

    if host_only and result.path not in ("", "/") or result.params or result.query or \
            result.fragment:
        print("result", result)
        raise UrlValidationError(UrlValidationError.ONLY_HOST_WANTED)

    return url
