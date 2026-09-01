"""Check 3.10 — the OAuth discovery chain.

Seven verdict-bearing legs, ``3.10a`` to ``3.10g``, recorded under
``details["legs"]``. Two further legs of the recommendation carry no verdict:
``3.10h`` is the host guard every server-supplied discovery URL passes before it
is fetched, which is a property of this probe rather than of the server, and
``3.10i`` covers write permissions on whatever the server serves its metadata
from, which no remote client can observe.

The MCP endpoint's own scheme is check 2.2's verdict. Here it is a precondition:
an endpoint that is not https leaves no chain below it to assess, and grading it
again would fail 3.10 for a property 2.2 already reported.
"""

from __future__ import annotations

import json

from mcp.shared.auth_utils import resource_url_from_server_url

from ... import baseline
from ...client import AS_LIST_CAP, DISCOVERY_TIMEOUT
from ...context import ProbeContext
from ...netguard import resource_covers, scheme_of
from ..base import Check, CheckResult, Level, register
from .observations import attempted, attempted_for, guard_refused, unread

# The parent-prefix rule is wider than the exact string match the audit script
# applies, so every 3.10d outcome states it.
RESOURCE_RULE = (
    "the probe applies the SDK's parent-prefix rule (same origin, canonical path "
    "at or below the advertised path) rather than the audit's exact string match"
)


def _is_tls(url: str) -> bool:
    """True when ``url`` is served over https.

    A URL that cannot be parsed is not https. One of the discovery paths is built
    from a header the server sent, so this must answer rather than raise.
    """
    return scheme_of(url) == "https"


def _as_list_ok(document: dict) -> bool:
    """True when ``document`` advertises at least one authorization server.

    An empty or absent ``authorization_servers`` list is protocol-invalid, and so
    is any value that is not a list of non-blank strings.
    """
    return bool(_advertised_servers(document))


def _documents_agree(one: dict, other: dict) -> bool:
    """True when two documents are byte-equal after a canonical key sort."""
    return json.dumps(one, sort_keys=True) == json.dumps(other, sort_keys=True)


def _advertised_servers(document: dict) -> list[str]:
    """The usable ``authorization_servers`` entries, in advertised order.

    The document is server-controlled, so every element is type-checked.
    """
    advertised = document.get("authorization_servers")
    if not isinstance(advertised, list):
        return []
    return [e for e in advertised if isinstance(e, str) and e.strip()]


@register
class DiscoveryChainIntegrity(Check):
    id = "3.10"
    title = (
        "OAuth discovery metadata is served over TLS and validated against the "
        "approved authorization server list"
    )
    section = "3"
    level = Level.L2
    remediation = (
        "Serve one protected-resource metadata document over TLS at every "
        "discovery path the client may try, with a resource value equal to the "
        "server's canonical URI and a non-empty authorization_servers list; make "
        "each advertised authorization server publish metadata whose issuer "
        "string-equals the advertised entry; and change-control the advertised "
        "list so a new authorization server cannot appear unreviewed."
    )

    async def run(self, ctx: ProbeContext) -> CheckResult:
        endpoint = ctx.endpoint_url
        if not endpoint:
            return self._error("no live session to test against")

        # 3.10a, the precondition. Check 2.2 owns the endpoint's TLS verdict.
        if not _is_tls(endpoint):
            return self._unknown(
                f"3.10a: the MCP endpoint {endpoint} is not served over TLS, so "
                "the discovery chain below it cannot be assessed. Check 2.2 owns "
                "the transport-security verdict and reports it there",
                legs={"3.10a": "unknown"},
            )

        if not ctx.prm_documents:
            # No document read, and two very different reasons for that. Every
            # path answering a clean 404 is the server stating that it publishes
            # none, and the recommendation is then vacuous. Anything else --
            # an error, a refusal, another status, or no attempt recorded at all
            # -- means we never got that statement, so neither outcome is
            # observed and there is nothing to call vacuous.
            attempts = attempted(ctx, "prm:")
            refused = guard_refused(ctx, "prm:") + guard_refused(ctx, "as:")
            why = unread(ctx, "prm:")
            if why:
                return self._unknown(
                    "no protected-resource metadata was read, and no discovery "
                    "path answered that the server publishes none: "
                    + "; ".join(why)
                    + ". Whether a discovery chain exists here is undecided, so "
                    "this run neither grades the chain nor rules the "
                    "recommendation out",
                    legs={"3.10a": "pass"},
                    discovery_attempts=attempts,
                    guard_refused_urls=refused,
                )
            # Every path answered a clean 404, so the absence was observed rather
            # than assumed. What that absence means depends on whether the server
            # does OAuth at all. Checks 3.5 and 3.8 draw the same line.
            offers_oauth = bool(
                ctx.auth_required
                or ctx.access_token
                or ctx.as_metadata_by_issuer
                or ctx.challenge_scope
            )
            if offers_oauth:
                return self._fail(
                    "the server requires OAuth and every discovery path answered "
                    "404, so it publishes no protected-resource metadata at all. A "
                    "client has no way to discover the authorization server, which "
                    "is what this recommendation exists to guarantee. The absence "
                    "was observed on every path rather than assumed",
                    legs={"3.10a": "pass"},
                    discovery_attempts=attempts,
                    guard_refused_urls=refused,
                )
            return self._na(
                "every discovery path answered 404 and the server offers no OAuth "
                "at all, so it published no protected-resource metadata, there is "
                "no discovery chain to assess and the recommendation is vacuous "
                "for this target. The audit reports ERROR for a chain that "
                "resolves to nothing; this probe reports NOT_APPLICABLE, because "
                "ERROR is reserved for a failure on our side and a server that "
                "never offered OAuth is not one",
                legs={"3.10a": "pass"},
                discovery_attempts=attempts,
                guard_refused_urls=refused,
            )

        document = ctx.protected_resource_metadata or {}
        advertised = _advertised_servers(document)
        refused = guard_refused(ctx, "prm:") + guard_refused(ctx, "as:")

        legs = [
            (
                "3.10a",
                "pass",
                f"the MCP endpoint {endpoint} is served over TLS",
            ),
            self._paths_agree(ctx),
            self._document_over_tls(ctx),
            self._resource_matches(document, endpoint),
            self._servers_advertised(document, advertised),
            self._within_baseline(ctx),
            self._issuers_match(ctx, advertised),
        ]

        past_cap = max(0, len(advertised) - AS_LIST_CAP)
        evidence = "; ".join(f"{leg}: {note}" for leg, _, note in legs)
        evidence += (
            f". Discovery is bounded: at most {AS_LIST_CAP} advertised "
            f"authorization server(s) are resolved ({len(advertised)} advertised, "
            f"{past_cap} past the cap left unresolved) and every discovery fetch "
            f"uses a fixed {DISCOVERY_TIMEOUT:.0f}s timeout, so a longer "
            "advertised list is assessed only as far as the cap"
        )

        details = {
            "legs": {leg: outcome for leg, outcome, _ in legs},
            "discovery_paths_answered": sorted(ctx.prm_documents),
            "authorization_servers_advertised": len(advertised),
            "authorization_servers_resolved": len(ctx.as_metadata_by_issuer),
            "authorization_servers_cap": AS_LIST_CAP,
            "authorization_servers_past_cap": past_cap,
            "discovery_timeout_seconds": DISCOVERY_TIMEOUT,
            "guard_refused_urls": refused,
        }

        outcomes = [outcome for _, outcome, _ in legs]
        if "fail" in outcomes:
            return self._fail(evidence, **details)
        if "error" in outcomes:
            return self._error(evidence, **details)
        if "unknown" in outcomes:
            return self._unknown(evidence, **details)
        return self._pass(evidence, **details)

    # --- legs -------------------------------------------------------------
    def _paths_agree(self, ctx: ProbeContext) -> tuple[str, str, str]:
        """3.10b — the document a client selects agrees with the one the challenge names.

        Those two are the pair a conforming client reads, and they are the pair the
        audit compares. Every answering path is deliberately NOT compared against
        every other: RFC 9728 path-insertion exists so a server can serve one
        document per resource, and a client that got an answer from the inserted
        path never reads the root. Comparing them would fail a server for being
        conformant.
        """
        selected = ctx.protected_resource_metadata or {}
        challenge_url = ctx.challenge_resource_metadata
        advertised = ctx.prm_documents.get(challenge_url or "")

        if advertised is None:
            reason = (
                "the challenge named no metadata URL"
                if not challenge_url
                else f"the challenge named {challenge_url}, which served no document"
            )
            return (
                "3.10b",
                "pass",
                f"only one discovery document was consulted, because {reason}, so "
                "there is no second document to disagree with it. The "
                f"{len(ctx.prm_documents)} path(s) that answered are recorded, and "
                "paths a client would not read are not compared against each other",
            )
        if _documents_agree(selected, advertised):
            return (
                "3.10b",
                "pass",
                f"the document the challenge names ({challenge_url}) is byte-equal "
                "to the one a client selects, after a canonical key sort",
            )
        return (
            "3.10b",
            "fail",
            f"the document the challenge names ({challenge_url}) differs from the "
            "one a client selects, after a canonical key sort",
        )

    def _document_over_tls(self, ctx: ProbeContext) -> tuple[str, str, str]:
        """3.10c — the metadata document is served only over TLS."""
        plain = sorted(url for url in ctx.prm_documents if not _is_tls(url))
        if plain:
            return (
                "3.10c",
                "fail",
                "protected-resource metadata was served over a non-TLS URL: "
                + ", ".join(plain),
            )
        refused = guard_refused(ctx, "prm:")
        if refused:
            return (
                "3.10c",
                "unknown",
                "the host guard refused a discovery URL the server supplied, so "
                "it was never fetched and its scheme was never observed: "
                + ", ".join(refused),
            )
        return (
            "3.10c",
            "pass",
            f"every one of the {len(ctx.prm_documents)} discovery path(s) that "
            "answered was https",
        )

    def _resource_matches(self, document: dict, endpoint: str) -> tuple[str, str, str]:
        """3.10d — the advertised resource covers the canonical URI."""
        canonical = resource_url_from_server_url(endpoint)
        advertised = document.get("resource")
        if not isinstance(advertised, str) or not advertised.strip():
            return (
                "3.10d",
                "unknown",
                f"the protected-resource document carries no resource string, so "
                f"there was nothing to compare against the canonical URI "
                f"{canonical}; {RESOURCE_RULE}",
            )
        covers = resource_covers(advertised, canonical)
        if covers is None:
            # RFC 9728 requires this member to be a URI, and no conforming client
            # can parse this one. That is a violation we observed in the document
            # the server served, which is why it fails rather than staying
            # undecided: the value is present, readable, and wrong.
            return (
                "3.10d",
                "fail",
                f"the advertised resource {advertised!r} is not a parsable URI, so "
                f"it could not be compared with the canonical URI {canonical}; "
                f"{RESOURCE_RULE}",
            )
        if covers:
            relation = (
                "equals" if advertised == canonical else "is a hierarchical parent of"
            )
            return (
                "3.10d",
                "pass",
                f"the advertised resource {advertised} {relation} the canonical "
                f"URI {canonical}; {RESOURCE_RULE}",
            )
        return (
            "3.10d",
            "fail",
            f"the advertised resource {advertised} does not cover the canonical "
            f"URI {canonical}; {RESOURCE_RULE}",
        )

    def _servers_advertised(
        self, document: dict, advertised: list[str]
    ) -> tuple[str, str, str]:
        """3.10e — authorization_servers is present and non-empty."""
        if _as_list_ok(document):
            return (
                "3.10e",
                "pass",
                f"{len(advertised)} authorization server(s) advertised: "
                + ", ".join(advertised),
            )
        return (
            "3.10e",
            "fail",
            "the protected-resource document advertises no usable "
            "authorization_servers entry, which is protocol-invalid: a document "
            f"was served, so the requirement applies (value: "
            f"{document.get('authorization_servers')!r})",
        )

    def _within_baseline(self, ctx: ProbeContext) -> tuple[str, str, str]:
        """3.10f — the advertised list is within the recorded baseline."""
        if ctx.update_baseline:
            return (
                "3.10f",
                "unknown",
                "this run captures the baseline instead of comparing against it, "
                "so it decides nothing about the advertised list",
            )
        record = baseline.load(ctx.endpoint_url or "")
        if record is None:
            return (
                "3.10f",
                "unknown",
                "no baseline recorded for this endpoint yet; run once with "
                "--update-baseline to establish one",
            )
        added, missing_in = baseline.compare_category(
            record, baseline.snapshot(ctx), "authorization_servers"
        )
        if missing_in == "record":
            return (
                "3.10f",
                "unknown",
                "the baseline record carries no authorization_servers category, "
                "so this run cannot tell an addition from a first observation",
            )
        if missing_in == "current":
            return (
                "3.10f",
                "unknown",
                "this run observed no advertised authorization_servers list, so "
                "there is nothing to compare against the recorded one",
            )
        if added:
            return (
                "3.10f",
                "fail",
                "authorization server(s) advertised but not in the recorded "
                "baseline: " + ", ".join(added),
            )
        return (
            "3.10f",
            "pass",
            "every advertised authorization server is in the recorded baseline",
        )

    def _issuers_match(
        self, ctx: ProbeContext, advertised: list[str]
    ) -> tuple[str, str, str]:
        """3.10g — each advertised authorization server publishes a matching issuer."""
        if not advertised:
            return (
                "3.10g",
                "unknown",
                "no authorization server was advertised, so no issuer could be "
                "resolved",
            )

        matched: list[str] = []
        mismatched: list[str] = []
        unresolved: list[str] = []
        for entry in advertised[:AS_LIST_CAP]:
            metadata = ctx.as_metadata_by_issuer.get(entry)
            if metadata is None:
                unresolved.append(entry)
            elif metadata.get("issuer") == entry:
                matched.append(entry)
            else:
                mismatched.append(f"{entry} publishes {metadata.get('issuer')!r}")

        if mismatched:
            return (
                "3.10g",
                "fail",
                "advertised authorization server(s) publish a different issuer: "
                + "; ".join(mismatched),
            )
        if unresolved:
            # Each issuer's own attempts, told apart from an issuer that extends
            # it, so both the refusal and the count below speak for one entry.
            attempts = {
                entry: attempted_for(ctx, "as:", entry, advertised)
                for entry in unresolved
            }
            refused = set(guard_refused(ctx, "as:"))
            blocked = [
                entry for entry in unresolved if refused.intersection(attempts[entry])
            ]
            if blocked:
                return (
                    "3.10g",
                    "unknown",
                    "the host guard refused an authorization-server metadata URL, "
                    "so nothing was fetched and no issuer was observed for "
                    + ", ".join(blocked),
                )
            # The number of forms tried is a property of the issuer string --
            # an issuer carrying a path yields one more form than a root one --
            # so it is counted from the attempts actually recorded.
            tried = [
                f"{entry} ({len(attempts[entry])} discovery form(s) tried)"
                for entry in unresolved
            ]
            return (
                "3.10g",
                "error",
                "no discovery form served authorization-server metadata carrying "
                "an issuer, so no issuer was reached for " + "; ".join(tried),
            )
        return (
            "3.10g",
            "pass",
            f"each of the {len(matched)} advertised authorization server(s) "
            "publishes an issuer that string-equals the advertised entry, taking "
            "the first discovery form that yields an issuer",
        )


if __name__ == "__main__":
    # The SDK's hierarchical rule is what a conforming client applies. Pin it,
    # because 3.10d and 3.5a both depend on this behaviour. The advertised value
    # comes from the audited server, so the comparison runs through the wrapper
    # that answers None instead of raising on a string it cannot parse.
    # test-type: ground-truth-vendor | source: mcp.shared.auth_utils.check_resource_allowed
    # captured-from: mcp 1.28.1 | last-revalidated: 2026-09-01
    assert resource_covers("https://host", "https://host/mcp") is True
    assert resource_covers("https://host/mcp", "https://host/mcp") is True
    assert resource_covers("https://other", "https://host/mcp") is False
    assert resource_covers("https://exa[mple.com", "https://host/mcp") is None
    # The two live shapes this leg has actually met, both of which satisfy strict
    # equality. They pin the inputs rather than the hierarchical rule above.
    assert resource_covers("https://mcp.linear.app/mcp", "https://mcp.linear.app/mcp")
    assert resource_covers("https://mcp.stripe.com", "https://mcp.stripe.com")
    # The scheme check: discovery must be served over TLS.
    assert not _is_tls("http://mcp.example.com/mcp")
    assert _is_tls("https://mcp.example.com/mcp")
    # An empty or absent authorization_servers list is protocol-invalid.
    assert _as_list_ok({"authorization_servers": ["https://as"]})
    assert not _as_list_ok({"authorization_servers": []})
    assert not _as_list_ok({})
    # Key order is not a disagreement; a differing value is.
    assert _documents_agree({"a": 1, "b": 2}, {"b": 2, "a": 1})
    assert not _documents_agree({"a": 1}, {"a": 2})

    # The applicability gate, over hand-built contexts and no network.
    import asyncio
    import tempfile
    from pathlib import Path

    from ...context import HttpObservation
    from ..base import Status

    # No self-check may read or write the records a real run keeps.
    baseline.DATA_DIR = Path(tempfile.mkdtemp()) / "baselines"

    ENDPOINT = "https://mcp.linear.app/mcp"
    PRM_A = "https://mcp.linear.app/.well-known/oauth-protected-resource/mcp"
    PRM_B = "https://mcp.linear.app/.well-known/oauth-protected-resource"
    DOC = {"resource": ENDPOINT, "authorization_servers": ["https://mcp.linear.app"]}

    def _obs(url: str, status: int | None, error: str | None = None) -> HttpObservation:
        return HttpObservation(url=url, method="GET", status=status, error=error)

    def _ctx(**kwargs) -> ProbeContext:
        return ProbeContext(
            domain="mcp.linear.app", base_url="https://mcp.linear.app", **kwargs
        )

    def _verdict(ctx: ProbeContext) -> CheckResult:
        return asyncio.run(DiscoveryChainIntegrity().run(ctx))

    # Nothing was reached at all, which is a failure on our own side.
    assert _verdict(_ctx()).status is Status.ERROR

    # OAuth is plainly on offer and every discovery attempt was stopped before
    # the server could answer: undecided, not inapplicable.
    stopped = _verdict(
        _ctx(
            endpoint_url=ENDPOINT,
            auth_required=True,
            http={
                f"prm:{PRM_A}": _obs(PRM_A, 502),
                f"prm:{PRM_B}": _obs(PRM_B, None, "guard-refused"),
            },
        )
    )
    assert stopped.status is Status.UNKNOWN, stopped.status
    assert stopped.details["guard_refused_urls"] == [PRM_B]
    assert stopped.details["discovery_attempts"] == sorted([PRM_A, PRM_B])
    assert "502" in stopped.evidence and "guard-refused" in stopped.evidence

    # test-type: regression | source: live run 2026-09-01 against
    # mcp.atlassian.com/v1/mcp -- an authenticated run whose discovery paths all
    # answered 404 reported NOT_APPLICABLE, calling the recommendation vacuous for a
    # server that requires OAuth.
    #
    # Every discovery path answered a clean 404, so the absence was observed. What it
    # means splits on whether the server does OAuth at all.
    _absent_http = {f"prm:{PRM_A}": _obs(PRM_A, 404), f"prm:{PRM_B}": _obs(PRM_B, 404)}
    # A server that requires OAuth and publishes nothing: a client cannot discover
    # the authorization server, which is the failure this recommendation names.
    demands_oauth = _verdict(
        _ctx(endpoint_url=ENDPOINT, auth_required=True, http=_absent_http)
    )
    assert demands_oauth.status is Status.FAIL, demands_oauth.status
    assert "requires OAuth" in demands_oauth.evidence, demands_oauth.evidence
    # An access token alone counts as OAuth, with no 401 recorded.
    assert (
        _verdict(
            _ctx(endpoint_url=ENDPOINT, access_token="t", http=_absent_http)
        ).status
        is Status.FAIL
    )
    # A server offering no OAuth at all: the recommendation really is vacuous.
    absent = _verdict(_ctx(endpoint_url=ENDPOINT, http=_absent_http))
    assert absent.status is Status.NOT_APPLICABLE, absent.status
    assert absent.details["guard_refused_urls"] == []
    assert absent.details["discovery_attempts"] == sorted([PRM_A, PRM_B])

    # A 200 whose body was not read as a document is not that answer either.
    served = _verdict(
        _ctx(
            endpoint_url=ENDPOINT,
            auth_required=True,
            http={f"prm:{PRM_A}": _obs(PRM_A, 200)},
        )
    )
    assert served.status is Status.UNKNOWN, served.status
    assert f"{PRM_A} (200)" in served.evidence

    # A healthy document still runs every leg. update_baseline keeps 3.10f off
    # the stored baseline, which is state from earlier runs rather than input.
    healthy = _verdict(
        _ctx(
            endpoint_url=ENDPOINT,
            auth_required=True,
            update_baseline=True,
            protected_resource_metadata=DOC,
            prm_documents={PRM_A: DOC},
            as_metadata_by_issuer={
                "https://mcp.linear.app": {"issuer": "https://mcp.linear.app"}
            },
            http={f"prm:{PRM_A}": _obs(PRM_A, 200)},
        )
    )
    legs = healthy.details["legs"]
    assert [legs[leg] for leg in ("3.10a", "3.10b", "3.10c", "3.10d", "3.10e")] == [
        "pass"
    ] * 5, legs
    assert legs["3.10g"] == "pass", legs
    assert legs["3.10f"] == "unknown", legs

    # 3.10g states how many discovery forms it tried, counted from the attempts
    # recorded: three for an issuer carrying a path, two for a root issuer.
    ISSUER = "https://as.example.com/mcp"
    AS_FORMS = [
        "https://as.example.com/.well-known/oauth-authorization-server/mcp",
        "https://as.example.com/.well-known/openid-configuration/mcp",
        "https://as.example.com/mcp/.well-known/openid-configuration",
    ]
    unreached_doc = {"resource": ENDPOINT, "authorization_servers": [ISSUER]}
    unreached = _verdict(
        _ctx(
            endpoint_url=ENDPOINT,
            auth_required=True,
            update_baseline=True,
            protected_resource_metadata=unreached_doc,
            prm_documents={PRM_A: unreached_doc},
            http={f"prm:{PRM_A}": _obs(PRM_A, 200)}
            | {f"as:{ISSUER}:{url}": _obs(url, 404) for url in AS_FORMS},
        )
    )
    assert unreached.details["legs"]["3.10g"] == "error", unreached.details["legs"]
    assert f"{ISSUER} (3 discovery form(s) tried)" in unreached.evidence

    # Two advertised issuers where one is a string-prefix of the other --
    # here, an explicit port on the same host -- must each report their own
    # attempt count, not have the shorter one absorb the longer one's.
    SHORT_ISSUER = "https://as.example.com"
    LONG_ISSUER = "https://as.example.com:8443"
    SHORT_FORMS = [
        "https://as.example.com/.well-known/oauth-authorization-server",
        "https://as.example.com/.well-known/openid-configuration",
    ]
    LONG_FORMS = [
        "https://as.example.com:8443/.well-known/oauth-authorization-server",
        "https://as.example.com:8443/.well-known/openid-configuration",
        "https://as.example.com:8443/mcp/.well-known/openid-configuration",
    ]
    collision_doc = {
        "resource": ENDPOINT,
        "authorization_servers": [SHORT_ISSUER, LONG_ISSUER],
    }
    collision_ctx = _ctx(
        endpoint_url=ENDPOINT,
        auth_required=True,
        update_baseline=True,
        protected_resource_metadata=collision_doc,
        prm_documents={PRM_A: collision_doc},
        http={f"prm:{PRM_A}": _obs(PRM_A, 200)}
        | {f"as:{SHORT_ISSUER}:{url}": _obs(url, 404) for url in SHORT_FORMS}
        | {f"as:{LONG_ISSUER}:{url}": _obs(url, 404) for url in LONG_FORMS},
    )
    # The full advertised list is what lets the reader tell these two apart: with
    # only the issuer it is asked about, the shorter one claims all five URLs.
    both = [SHORT_ISSUER, LONG_ISSUER]
    assert attempted_for(collision_ctx, "as:", SHORT_ISSUER, both) == sorted(
        SHORT_FORMS
    ), attempted_for(collision_ctx, "as:", SHORT_ISSUER, both)
    assert attempted_for(collision_ctx, "as:", LONG_ISSUER, both) == sorted(
        LONG_FORMS
    ), attempted_for(collision_ctx, "as:", LONG_ISSUER, both)

    collision = _verdict(collision_ctx)
    assert collision.details["legs"]["3.10g"] == "error", collision.details["legs"]
    assert f"{SHORT_ISSUER} (2 discovery form(s) tried)" in collision.evidence
    assert f"{LONG_ISSUER} (3 discovery form(s) tried)" in collision.evidence

    # The ordinary single-issuer case (no colliding neighbour) still reports
    # its own count correctly -- the fix has not broken the normal path.
    assert f"{ISSUER} (3 discovery form(s) tried)" in unreached.evidence

    # 3.10g's refusal message names only the issuer it describes. Both advertised
    # issuers went unresolved here; only the first had a URL the guard refused,
    # and the second answered 404, so a message covering both would speak for an
    # issuer whose fetch the guard never touched.
    REFUSED_ISSUER = "https://as-blocked.example.com"
    ANSWERED_ISSUER = "https://as-open.example.com"
    refused_url = f"{REFUSED_ISSUER}/.well-known/oauth-authorization-server"
    open_url = f"{ANSWERED_ISSUER}/.well-known/oauth-authorization-server"
    scoped_ctx = _ctx(
        endpoint_url=ENDPOINT,
        auth_required=True,
        update_baseline=True,
        http={
            f"as:{REFUSED_ISSUER}:{refused_url}": _obs(
                refused_url, None, "guard-refused"
            ),
            f"as:{ANSWERED_ISSUER}:{open_url}": _obs(open_url, 404),
        },
    )
    _leg, outcome, note = DiscoveryChainIntegrity()._issuers_match(
        scoped_ctx, [REFUSED_ISSUER, ANSWERED_ISSUER]
    )
    assert outcome == "unknown", (outcome, note)
    assert REFUSED_ISSUER in note, note
    assert ANSWERED_ISSUER not in note, note

    # 3.10d over all three answers the guarded comparison gives. The advertised
    # value comes from the audited server, so a string no client can parse has to
    # end in a verdict: an exception here would discard every leg already decided.
    def _resource_leg(resource: str) -> tuple[str, CheckResult]:
        """Run the check over a document advertising ``resource``, return leg 3.10d."""
        doc = {
            "resource": resource,
            "authorization_servers": ["https://mcp.linear.app"],
        }
        result = _verdict(
            _ctx(
                endpoint_url=ENDPOINT,
                auth_required=True,
                update_baseline=True,
                protected_resource_metadata=doc,
                prm_documents={PRM_A: doc},
                as_metadata_by_issuer={
                    "https://mcp.linear.app": {"issuer": "https://mcp.linear.app"}
                },
                http={f"prm:{PRM_A}": _obs(PRM_A, 200)},
            )
        )
        return result.details["legs"]["3.10d"], result

    # An advertised hierarchical parent covers the canonical URI.
    outcome, _result = _resource_leg("https://mcp.linear.app")
    assert outcome == "pass", outcome
    # A different origin does not.
    outcome, _result = _resource_leg("https://other.example.com")
    assert outcome == "fail", outcome
    # An unparsable value is a violation of the document's own requirement, so it
    # fails on its own terms, names itself, and leaves the other legs decided.
    MALFORMED = "https://exa[mple.com"
    outcome, result = _resource_leg(MALFORMED)
    assert outcome == "fail", outcome
    assert MALFORMED in result.evidence, result.evidence
    assert "not a parsable URI" in result.evidence, result.evidence
    assert "could not be compared" in result.evidence, result.evidence
    assert result.details["legs"]["3.10e"] == "pass", result.details["legs"]

    # 3.10f decides only when both sides were observed, and the three cases below
    # are what "observed" means for this category. The check's own verdict is not
    # asserted here, because 3.10e fails on two of these documents; the leg's
    # recorded outcome is the subject.
    RECORD = {"endpoint": ENDPOINT, "authorization_servers": ["https://mcp.linear.app"]}
    baseline.save(ENDPOINT, RECORD)
    leg = DiscoveryChainIntegrity()._within_baseline

    # A document that answered and advertises none is an observed absence, the same
    # rule leg 3.8f applies to scopes_supported in that document. Nothing was added,
    # so the leg decides and passes rather than reporting a blind side.
    NO_LIST_DOC = {"resource": ENDPOINT}
    read_it = _ctx(
        endpoint_url=ENDPOINT,
        auth_required=True,
        protected_resource_metadata=NO_LIST_DOC,
        prm_documents={PRM_A: NO_LIST_DOC},
        http={f"prm:{PRM_A}": _obs(PRM_A, 200)},
    )
    assert leg(read_it)[1] == "pass", leg(read_it)

    # The decided fail path: a server advertised that the record does not hold.
    ADDED_DOC = {"resource": ENDPOINT, "authorization_servers": ["https://new.example"]}
    added_ctx = _ctx(
        endpoint_url=ENDPOINT,
        auth_required=True,
        protected_resource_metadata=ADDED_DOC,
        prm_documents={PRM_A: ADDED_DOC},
        http={f"prm:{PRM_A}": _obs(PRM_A, 200)},
    )
    _leg_id, outcome, note = leg(added_ctx)
    assert outcome == "fail" and "https://new.example" in note, (outcome, note)

    # The blind-current branch. `run` returns before this leg when no document was
    # read, so the leg is called directly: the branch is the guard that holds if
    # that early return ever moves.
    blind = _ctx(endpoint_url=ENDPOINT, auth_required=True)
    _leg_id, outcome, note = leg(blind)
    assert outcome == "unknown", (outcome, note)
    assert "this run observed no advertised authorization_servers" in note, note

    # test-type: regression | source: live run 2026-09-01 against mcp.notion.com --
    # a server serving one document per resource was reported FAIL on leg 3.10b, while
    # the benchmark's own audit passes it. The audit reads the path-inserted form and
    # compares it against the challenge-advertised document; it never compares the root
    # form against the inserted one, because a client that got an answer from
    # path-insertion never reads the root.
    #
    # The two documents below are vendor-owned shapes, so they carry their own
    # provenance:
    # captured-from: mcp.notion.com, both well-known paths, 2026-09-01
    # last-revalidated: 2026-09-01
    # These fixtures never touch the network, so they cannot detect drift. If Notion
    # stops serving one document per resource, they keep passing while no longer
    # describing anything real. Re-read both paths when revalidating, and expect the
    # `resource` values to be the only difference between them.
    NOTION_SUB = {
        "resource": "https://mcp.notion.com/mcp",
        "authorization_servers": ["https://mcp.notion.com"],
    }
    NOTION_ROOT = {
        "resource": "https://mcp.notion.com",
        "authorization_servers": ["https://mcp.notion.com"],
    }
    SUB_URL = "https://mcp.notion.com/.well-known/oauth-protected-resource/mcp"
    ROOT_URL = "https://mcp.notion.com/.well-known/oauth-protected-resource"
    agree = DiscoveryChainIntegrity()._paths_agree(
        ProbeContext(
            domain="mcp.notion.com",
            base_url="https://mcp.notion.com",
            endpoint_url="https://mcp.notion.com/mcp",
            protected_resource_metadata=NOTION_SUB,
            prm_documents={SUB_URL: NOTION_SUB, ROOT_URL: NOTION_ROOT},
            challenge_resource_metadata=SUB_URL,
        )
    )
    assert agree[1] == "pass", agree
    assert "byte-equal" in agree[2], agree[2]

    # A challenge pointing at a document that really does disagree with the selected
    # one is the case the leg exists for, and it still fails.
    disagree = DiscoveryChainIntegrity()._paths_agree(
        ProbeContext(
            domain="mcp.notion.com",
            base_url="https://mcp.notion.com",
            endpoint_url="https://mcp.notion.com/mcp",
            protected_resource_metadata=NOTION_SUB,
            prm_documents={SUB_URL: NOTION_SUB, ROOT_URL: NOTION_ROOT},
            challenge_resource_metadata=ROOT_URL,
        )
    )
    assert disagree[1] == "fail", disagree

    # A challenge that named no URL leaves one document, which cannot disagree with
    # itself. Two answering paths are still recorded, and still not compared.
    alone = DiscoveryChainIntegrity()._paths_agree(
        ProbeContext(
            domain="d",
            base_url="https://d",
            endpoint_url="https://d/mcp",
            protected_resource_metadata=NOTION_SUB,
            prm_documents={SUB_URL: NOTION_SUB, ROOT_URL: NOTION_ROOT},
        )
    )
    assert alone[1] == "pass" and "no metadata URL" in alone[2], alone

    print("c310: all self-checks passed")
