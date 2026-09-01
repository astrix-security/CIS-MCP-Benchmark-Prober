"""Read what the discovery fetches observed, from one place.

One distinction, easy to get backwards: the server served no document, versus we
never read one. The first is an observation and can earn a failure. The second
says nothing about the server and cannot.

Every fetch is recorded in ``ctx.http`` under a prefix naming what it was for --
``prm:`` for protected-resource metadata, ``as:`` for authorization-server
metadata. These are the only readers of those labels, so the rule cannot differ
between the checks that consult it. A prefix whose documents were parsed was
observed whatever status its attempts carried, and that precondition lives here
rather than with each caller: three copies of it once disagreed.
"""

from __future__ import annotations

from collections.abc import Callable

from .context import ProbeContext

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
    colon-extension of another -- the same host with an explicit port. A plain
    prefix test would let the shorter issuer absorb the longer one's attempts, so a
    label counts for ``key`` only when no other entry claims it more specifically.
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
    no document. Anything else leaves it unobserved.
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

    Distinct from every attempt failing: discovery can stop before trying a single
    path, and the absence is then a fact about this run rather than the server.
    """
    return [
        _DESCRIBED.get(prefix, prefix)
        for prefix in prefixes
        if not _labelled(ctx, prefix) and not _was_parsed(ctx, prefix)
    ]


def unread(ctx: ProbeContext, *prefixes: str) -> list[str]:
    """Why nothing under ``prefixes`` was read, or [] when the absence was observed.

    The one call most checks want. [] means every path answered a clean 404, which
    is the server telling us it serves none.
    """
    failed = unanswered(ctx, *prefixes)
    if failed:
        return failed
    missing = never_attempted(ctx, *prefixes)
    if missing:
        return [f"no {name} discovery was attempted at all" for name in missing]
    return []
