"""Where may a bearer credential be sent? Decide first, attach second.

PROVENANCE
    Written for this showcase to demonstrate a control pattern used in the private
    system. It is not a copy of a private module: the structure, the policy object,
    the reason codes and the exposition here are specific to this file. No live
    endpoint, credential, audience, service identity or deployment configuration
    appears; `ALLOWED_HOST` is a placeholder. Standard library only.

THE BUG THIS EXISTS FOR

`urllib.request`'s default opener follows redirects, and when it builds the
redirected request its handler drops exactly two headers:

    CONTENT_HEADERS = ("content-length", "content-type")

`Authorization` survives that list and is copied onto the new request, whatever
host the new request points at. One `302` from an on-path attacker, a hijacked
DNS record, or a misconfigured service is therefore enough to hand a bearer
token to whoever wrote the `Location` header.

Checking the URL you passed in does not help, because the URL you passed in is
not the URL that receives the header:

    validated:  https://api.example.com/statuses/abc
    302 ->      https://collector.evil.test/           <- gets the Authorization

So the control cannot be "start somewhere safe". It has to be "never end up
anywhere unexamined", which is two rules:

    1. no redirect is followed, ever;
    2. the destination is fully parsed and approved before a credential exists
       on the request at all.

DESIGN NOTES

`DestinationPolicy` holds the rules as data so that a call site cannot forget one
and a test can name them individually. It is frozen: a policy that a caller could
mutate is not a policy.

Each rule returns a *reason code* rather than a boolean, because a control that
only says "no" is indistinguishable from a control that has stopped working. The
tests assert the code, not just the refusal.

Rejection is preferred to normalisation throughout. Userinfo, odd ports and
fragments could all be stripped and the request sent anyway. But a URL carrying
them is not the URL the caller believes it is, and the safe answer to "this is
not what you meant" is to stop rather than to guess.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

DEFAULT_TIMEOUT_SECONDS = 30
USER_AGENT = "representative-credential-safe-transport"

#: Placeholder. In a real service this is a constant the service owns -- never a
#: value a caller can supply, or "authenticate here" becomes "send it there".
ALLOWED_HOST = "api.example.com"


class CredentialTransportError(RuntimeError):
    """Refusal. Nothing was sent, and nothing will be retried elsewhere."""


@dataclass(frozen=True)
class DestinationPolicy:
    """The rules a URL must satisfy before a credential may be attached to it."""

    allowed_host: str = ALLOWED_HOST
    allowed_scheme: str = "https"
    allowed_port: int = 443
    allow_query: bool = True

    def approve(self, url: str) -> str:
        """Return `url` unchanged if it satisfies every rule, else raise.

        Ordered so that the cheapest structural failures are reported first and
        so that nothing downstream ever runs against a value it could not parse.
        """
        parts = self._parse(url)
        for check in (self._scheme, self._userinfo, self._host,
                      self._port, self._fragment, self._query):
            failure = check(parts)
            if failure:
                raise CredentialTransportError(failure)
        return url

    # -- individual rules -------------------------------------------------
    #
    # Each returns None to approve, or a "CODE: explanation" string to refuse.
    # Split up so a mutation harness can remove exactly one of them, and so a
    # test can name the one it is exercising.

    @staticmethod
    def _parse(url: str) -> urllib.parse.SplitResult:
        if not isinstance(url, str) or not url:
            raise CredentialTransportError("DESTINATION_MISSING: no URL supplied")
        try:
            return urllib.parse.urlsplit(url)
        except ValueError as exc:
            raise CredentialTransportError(f"DESTINATION_UNPARSEABLE: {exc}") from None

    def _scheme(self, parts) -> str | None:
        if parts.scheme != self.allowed_scheme:
            return (f"DESTINATION_NOT_HTTPS: scheme {parts.scheme!r} would carry the "
                    f"credential in the clear")
        return None

    def _userinfo(self, parts) -> str | None:
        # `https://api.example.com@evil.test/x` has hostname `evil.test`. To a
        # person reading it quickly it has hostname `api.example.com`. Refusing
        # userinfo outright removes the ambiguity rather than resolving it.
        if parts.username is not None or parts.password is not None:
            return ("DESTINATION_HAS_USERINFO: userinfo in the authority disguises "
                    "which host the request actually reaches")
        return None

    def _host(self, parts) -> str | None:
        host = parts.hostname
        if not host:
            return "DESTINATION_HAS_NO_HOST: nothing to authenticate to"
        # Equality, not a prefix or suffix test:
        #   "https://api.example.com.evil.test".startswith("https://api.example.com")
        # is True, and the registrable domain there is evil.test.
        if host != self.allowed_host:
            return (f"DESTINATION_HOST_NOT_ALLOWED: {host!r} is not "
                    f"{self.allowed_host!r}")
        return None

    def _port(self, parts) -> str | None:
        try:
            port = parts.port
        except ValueError as exc:
            return f"DESTINATION_PORT_MALFORMED: {exc}"
        if port is not None and port != self.allowed_port:
            return (f"DESTINATION_PORT_NOT_ALLOWED: {port} is not "
                    f"{self.allowed_port}")
        return None

    @staticmethod
    def _fragment(parts) -> str | None:
        # A fragment is never transmitted, so it cannot be doing anything useful
        # here. Its presence means the URL was built by something that thinks
        # this is a browser destination, which is worth stopping for.
        if parts.fragment:
            return ("DESTINATION_HAS_FRAGMENT: a fragment is never sent, so its "
                    "presence means this URL is not what the caller thinks")
        return None

    def _query(self, parts) -> str | None:
        if parts.query and not self.allow_query:
            return ("DESTINATION_HAS_QUERY: this endpoint is an exact address, "
                    "not a search")
        return None


DEFAULT_POLICY = DestinationPolicy()


def validate_credential_destination(url: str, *, allowed_host: str = ALLOWED_HOST,
                                    allow_query: bool = True) -> str:
    """Approve `url` as a credential destination, or raise. Convenience wrapper."""
    return DestinationPolicy(
        allowed_host=allowed_host, allow_query=allow_query).approve(url)


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    """Refuse at the moment the redirected request would be built.

    `redirect_request` is where `urllib` constructs the follow-up `Request` and
    copies the surviving headers onto it. Raising here is not "we sent it and
    then regretted it" -- the request bearing the credential is never built.

    Every redirect is refused, not merely cross-origin ones. No caller here needs
    a same-origin redirect, and permitting them would require deciding what
    "same origin" means, which is a question that gets answered once, slightly
    wrong, and then relied on.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise CredentialTransportError(
            f"REDIRECT_REFUSED: declining to follow HTTP {code}; a request "
            f"carrying a credential is never re-aimed by its response")


def request(method: str, url: str, *, headers=None, body=None,
            timeout: int = DEFAULT_TIMEOUT_SECONDS, allowed_host: str = ALLOWED_HOST,
            allow_query: bool = True, ssl_context=None, opener=None):
    """Send one request that may carry a credential. Returns `(status, bytes)`.

    Approval happens on the first line, before any header dict is assembled, so
    there is no point in time at which a rejected destination and an
    `Authorization` value coexist in a constructed request.

    `4xx` and `5xx` are returned rather than raised: what a refusal *means* is
    the caller's decision. `3xx` is never returned -- it is the failure mode this
    module exists to prevent.
    """
    target = validate_credential_destination(
        url, allowed_host=allowed_host, allow_query=allow_query)

    outgoing = {"User-Agent": USER_AGENT}
    outgoing.update(headers or {})

    prepared = urllib.request.Request(
        target, data=body, method=method, headers=outgoing)
    director = opener or urllib.request.build_opener(
        RefuseRedirects(),
        urllib.request.HTTPSHandler(context=ssl_context or ssl.create_default_context()))

    try:
        with director.open(prepared, timeout=timeout) as response:
            status, payload, answered_by = (
                response.status, response.read(), response.geturl())
    except urllib.error.HTTPError as exc:
        status, payload, answered_by = exc.code, exc.read(), exc.geturl()
        exc.close()
    except CredentialTransportError:
        raise
    except urllib.error.URLError as exc:
        raise CredentialTransportError(
            f"DESTINATION_UNREACHABLE: {type(exc).__name__}") from None

    # Two checks the handler above ought to have made unreachable. They are here
    # because "ought to" is not a control:
    #   - 300 and 305 are outside the set `redirect_request` is consulted for,
    #     as is anything the standard adds later;
    #   - a custom or reordered handler could return a redirect without the
    #     handler ever being asked.
    if 300 <= int(status) <= 399:
        raise CredentialTransportError(
            f"REDIRECT_REFUSED: HTTP {status} was returned and not followed")
    # Last line of defence: whatever answered must be what was approved.
    if answered_by != target:
        raise CredentialTransportError(
            f"DESTINATION_CHANGED: the response came from a URL that was never "
            f"approved")
    return int(status), payload
