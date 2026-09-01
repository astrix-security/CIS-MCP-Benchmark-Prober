"""Read what the discovery fetches observed, from one place.

Several checks need the same distinction, and it is easy to get backwards: the
server served no document, versus we never read one. The first is an observation
and can earn a failure. The second says nothing about the server and cannot.

Every fetch is recorded in ``ctx.http`` under a label that starts with a prefix
naming what it was for -- ``prm:`` for protected-resource metadata, ``as:`` for
authorization-server metadata. The functions here are the only readers of those
labels, so the rule they encode cannot differ between checks that consult it.

The precondition lives here rather than with each caller. A prefix whose
documents were parsed has been observed, whatever status its attempts carried,
so it contributes nothing to ``unanswered``. Callers that each remembered to
apply that themselves is exactly how three copies of this logic came to disagree.
"""

from __future__ import annotations

from collections.abc import Callable

from ...context import ProbeContext

# For each label prefix, the collection that proves its documents were read.
# ``unanswered`` consults this so a caller cannot forget to.
_PARSED: dict[str, Callable[[ProbeContext], object]] = {
    "prm:": lambda ctx: ctx.prm_documents,
    "as:": lambda ctx: ctx.as_metadata_by_issuer,
}

# What the label prefix means in a sentence an operator reads.
_DESCRIBED = {
    "prm:": "protected-resource metadata",
    "as:": "authorization-server metadata",
}


def _was_parsed(ctx: ProbeContext, prefix: str) -> bool:
    """Whether ``prefix``'s documents were parsed, so its fetches were observed."""
    parsed = _PARSED.get(prefix)
    return bool(parsed is not None and parsed(ctx))


def _labelled(ctx: ProbeContext, prefix: str):
    """Every recorded observation whose label starts with ``prefix``."""
    return [(label, obs) for label, obs in ctx.http.items() if label.startswith(prefix)]


def attempted(ctx: ProbeContext, prefix: str) -> list[str]:
    """The URLs fetched under ``prefix``, whatever came back."""
    return sorted(obs.url for _label, obs in _labelled(ctx, prefix))


def attempted_for(
    ctx: ProbeContext, prefix: str, key: str, keys: list[str]
) -> list[str]:
    """The URLs fetched under ``prefix`` for ``key`` alone.

    An ``as:`` label is ``as:<issuer>:<url>``, and one advertised issuer can be a
    colon-extension of another -- the same host with an explicit port is the
    plausible case. A plain prefix test would let the shorter issuer absorb the
    longer one's attempts, so a label counts for ``key`` only when no other
    advertised entry claims it more specifically.
    """
    mine = f"{prefix}{key}:"
    rivals = [
        f"{prefix}{other}:" for other in keys if other != key and other.startswith(key)
    ]
    return sorted(
        obs.url
        for label, obs in ctx.http.items()
        if label.startswith(mine) and not any(label.startswith(r) for r in rivals)
    )


def guard_refused(ctx: ProbeContext, *prefixes: str) -> list[str]:
    """The URLs under ``prefixes`` the host guard refused before any request."""
    return sorted(
        obs.url
        for prefix in prefixes
        for _label, obs in _labelled(ctx, prefix)
        if obs.error == "guard-refused"
    )


def unanswered(ctx: ProbeContext, *prefixes: str) -> list[str]:
    """The attempts under ``prefixes`` that left what they hold unobserved.

    Each entry reads ``<url> (<why>)``. A clean 404 is an answer: that path holds
    no document. Anything else -- a transport error, a host-guard refusal, a 403,
    a 502, or a 200 whose body was not a document -- leaves it unobserved.

    A prefix whose documents were parsed is skipped entirely. Reporting a URL that
    answered 200 and produced a document as "unobserved" states the opposite of
    what happened, and a caller reading this list puts it in front of an operator.
    """
    out: list[str] = []
    for prefix in prefixes:
        if _was_parsed(ctx, prefix):
            continue
        out.extend(
            f"{obs.url} ({obs.error or obs.status})"
            for _label, obs in _labelled(ctx, prefix)
            if obs.error or obs.status != 404
        )
    return sorted(out)


def never_attempted(ctx: ProbeContext, *prefixes: str) -> list[str]:
    """The prefixes under which nothing was fetched at all, described in words.

    Distinct from every attempt failing. Discovery can stop before it tries a
    single path, and then the absence of a document is a fact about this run
    rather than about the server.

    Holds the same precondition ``unanswered`` does, and for the same reason: a
    prefix whose documents were parsed was plainly reached, so it cannot also be
    reported as never attempted. Applying the rule in one of the two branches and
    not the other is how the copies of this logic disagreed in the first place.
    """
    return [
        _DESCRIBED.get(prefix, prefix)
        for prefix in prefixes
        if not _labelled(ctx, prefix) and not _was_parsed(ctx, prefix)
    ]


def unread(ctx: ProbeContext, *prefixes: str) -> list[str]:
    """Why nothing under ``prefixes`` was read, or [] when the absence was observed.

    The one call most checks want. It answers with the failed attempts when there
    were some, with a plain statement when nothing was attempted, and with an
    empty list when every path answered a clean 404 -- which is the server telling
    us it serves none.
    """
    failed = unanswered(ctx, *prefixes)
    if failed:
        return failed
    missing = never_attempted(ctx, *prefixes)
    if missing:
        return [f"no {name} discovery was attempted at all" for name in missing]
    return []


if __name__ == "__main__":
    from ...context import HttpObservation

    PRM = "https://mcp.example.com/.well-known/oauth-protected-resource"

    def _ctx(http=None, **fields) -> ProbeContext:
        ctx = ProbeContext(domain="d", base_url="https://d")
        ctx.endpoint_url = "https://d/mcp"
        for name, value in fields.items():
            setattr(ctx, name, value)
        for label, obs in (http or {}).items():
            ctx.http[label] = obs
        return ctx

    def _obs(url=PRM, status=None, error=None) -> HttpObservation:
        return HttpObservation(url=url, method="GET", status=status, error=error)

    # A path that answered a clean 404 is an observation: the server serves none.
    served_none = _ctx({f"prm:{PRM}": _obs(status=404)})
    assert unanswered(served_none, "prm:") == []
    assert unread(served_none, "prm:") == []

    # A path that failed leaves what it holds unobserved, and says why.
    for failure in (_obs(status=502), _obs(error="guard-refused"), _obs(status=200)):
        ctx = _ctx({f"prm:{PRM}": failure})
        assert len(unanswered(ctx, "prm:")) == 1, failure
        assert unread(ctx, "prm:") == unanswered(ctx, "prm:")

    # THE PRECONDITION. A 200 that produced a document was observed, so it is not
    # unanswered -- even though its status is not 404. Three separate copies of
    # this rule disagreed on exactly this case.
    read_it = _ctx(
        {f"prm:{PRM}": _obs(status=200)},
        prm_documents={PRM: {"resource": "https://d/mcp"}},
    )
    assert unanswered(read_it, "prm:") == [], unanswered(read_it, "prm:")
    assert unread(read_it, "prm:") == []

    # Nothing fetched at all is not the same as every path answering 404.
    nothing = _ctx()
    assert unanswered(nothing, "prm:") == []
    assert never_attempted(nothing, "prm:") == ["protected-resource metadata"]
    assert unread(nothing, "prm:") == [
        "no protected-resource metadata discovery was attempted at all"
    ]
    # and the served-none case must NOT report never-attempted
    assert never_attempted(served_none, "prm:") == []

    # A refusal is reported as itself, and only for the prefix asked about.
    refused = _ctx(
        {
            f"prm:{PRM}": _obs(error="guard-refused"),
            "as:https://as:u": _obs(url="u", status=404),
        }
    )
    assert guard_refused(refused, "prm:") == [PRM]
    assert guard_refused(refused, "as:") == []
    assert guard_refused(refused, "prm:", "as:") == [PRM]

    # Per-issuer attribution: one advertised issuer may be a colon-extension of
    # another, and the shorter one must not absorb the longer one's attempts.
    short, long = "https://as.example.com", "https://as.example.com:8443"
    ports = _ctx(
        {
            f"as:{short}:a": _obs(url="a", status=404),
            f"as:{short}:b": _obs(url="b", status=404),
            f"as:{long}:c": _obs(url="c", status=404),
        }
    )
    assert attempted_for(ports, "as:", short, [short, long]) == ["a", "b"]
    assert attempted_for(ports, "as:", long, [short, long]) == ["c"]
    # and the unfiltered reader still sees them all
    assert attempted(ports, "as:") == ["a", "b", "c"]

    # A parsed document proves the prefix was reached, so it cannot be reported as
    # never attempted either. Both branches consult the same predicate; honouring
    # it in one and not the other is the shape of bug this module exists to stop.
    parsed_no_record = _ctx(prm_documents={PRM: {"resource": "https://d/mcp"}})
    assert unanswered(parsed_no_record, "prm:") == []
    assert never_attempted(parsed_no_record, "prm:") == []
    assert unread(parsed_no_record, "prm:") == []
    # and a prefix with neither a record nor a parsed document is still missing
    assert never_attempted(_ctx(), "prm:") == ["protected-resource metadata"]
    print("observations: all self-checks passed")
