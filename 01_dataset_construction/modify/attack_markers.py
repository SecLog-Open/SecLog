"""
Generic attack-marker injection helpers for scene-side attack scripts.

Purpose (method layer, deliberately thin)
-----------------------------------------
In the SecLog labeling phase, strong seeds for applog write-gated
labeling come from three anchor points already recognised by
``sysdig_rules/__init__.py``:

    - ``openat(fd.name)`` containing ``ATK_FLAG_2``        -> log.malicious=True
    - ``write(evt.buffer) == "malicious"``                 -> log.malicious=True
    - ``execve(proc.env["malicious"]) == "true"``          -> log.malicious=True

For scenarios where the attack payload does **not** naturally land on
these paths (adminer/SSRF → file read being the first example), the
attacker needs a way to *carry* one of these markers through a request
component (query / form / header / path / filename / exec arg) so that
the server, while servicing the request, issues a syscall whose
attacker-controlled bytes contain the marker.

This module is the one place where the canonical marker constants live
for attacker-side code, and it offers a tiny, strategy-indexed set of
pure string helpers that any scene's ``attack.py`` can call. Nothing
here touches:

    - raw/applog / raw/sysdig / raw/tshark contents
    - log["malicious"] or node.is_malicious
    - the [*MALICIOUS*] prefix
    - weak / strong judgement in ``judge_applog_labels_at_write_level``
    - replay_index / build_behavior_chain_instances_v0.py

Scenes only pick:

    1. a *strategy*   (which kind of component carries the marker)
    2. a *field/index* (which specific field inside that component)

The judgement and the label pipeline are unchanged.

Usage pattern (attack.py inside the attacker container)::

    import sys
    sys.path.insert(0, "/attacker_lib")
    try:
        from attack_markers import ATK_FLAG_2, with_form_field
    except ImportError:
        with_form_field = None  # seed-only probe is best-effort

    data = {...original exploit payload...}
    requests.post(target_url, data=data)              # unchanged exploit

    if with_form_field is not None:                    # seed-only probe
        probe = with_form_field(data, "some_field", mode="suffix")
        requests.post(target_url, data=probe)

Adding a new scene is a one-liner in that scene's attack.py; no change
to this file, no change to ``sysdig_rules``.
"""

from __future__ import annotations

from typing import Mapping, Sequence

# Canonical markers. Kept in sync with sysdig_rules/__init__.py on
# purpose and NOT imported from there to avoid any attacker-side code
# having to pull in the host-side analyze stack.
ATK_FLAG_1 = "A#t#k#F#1#"
ATK_FLAG_2 = "A#t#k#F#2#"   # the anchor recognised inside openat(fd.name)
ATK_FLAG_3 = "A#t#k#F#3#"
DEFAULT_MARKER = ATK_FLAG_2


# --- strategy names are plain strings so attack scripts can pass them ---
# directly from scene config / CLI without importing an Enum. Any new
# strategy is additive; existing helpers keep working.
STRATEGY_QUERY = "query"
STRATEGY_FORM = "form"
STRATEGY_PATH = "path"
STRATEGY_HEADER = "header"
STRATEGY_FILENAME = "filename"
STRATEGY_EXEC_ARG = "exec_arg"


def _apply(
    base: str,
    marker: str,
    *,
    mode: str = "suffix",
    separator: str = "",
) -> str:
    """Combine ``base`` with ``marker``. Pure string op.

    mode:
      * ``suffix``  -> ``base + separator + marker`` (default)
      * ``prefix``  -> ``marker + separator + base``
      * ``replace`` -> ``marker`` (ignores base)
    """
    if mode == "suffix":
        return f"{base}{separator}{marker}"
    if mode == "prefix":
        return f"{marker}{separator}{base}"
    if mode == "replace":
        return marker
    raise ValueError(f"unknown mode: {mode!r} (expected suffix/prefix/replace)")


def with_form_field(
    form: Mapping[str, str],
    field: str,
    *,
    marker: str = DEFAULT_MARKER,
    mode: str = "suffix",
    separator: str = "",
) -> dict[str, str]:
    """Return a new form-dict where ``field`` carries ``marker``.

    Typical use — SSRF-style file-read exploits that smuggle a filename
    in a form field:

        probe = with_form_field(
            {"auth[username]": "fileread_/etc/passwd"},
            "auth[username]", mode="suffix",
        )
    """
    out = dict(form)
    base = out.get(field, "")
    out[field] = _apply(str(base), marker, mode=mode, separator=separator)
    return out


def with_query_param(
    url: str,
    param: str,
    *,
    marker: str = DEFAULT_MARKER,
    mode: str = "suffix",
    separator: str = "",
) -> str:
    """Return a URL with ``param`` carrying ``marker``.

    Existing ``param`` values are preserved; if absent, the marker is
    inserted as the new value (mode is still honoured so ``prefix`` /
    ``suffix`` with empty base both yield the marker itself).
    """
    from urllib.parse import parse_qsl, quote, urlencode, urlparse, urlunparse

    parts = urlparse(url)
    pairs = parse_qsl(parts.query, keep_blank_values=True)
    seen = False
    new_pairs: list[tuple[str, str]] = []
    for k, v in pairs:
        if k == param:
            new_pairs.append(
                (k, _apply(str(v), marker, mode=mode, separator=separator))
            )
            seen = True
        else:
            new_pairs.append((k, v))
    if not seen:
        new_pairs.append(
            (param, _apply("", marker, mode=mode, separator=separator))
        )
    # ``#`` in the canonical marker (A#t#k#F#2#) would normally be
    # percent-encoded by urlencode, which would make the literal token
    # vanish from the wire-format URL. We want the raw marker bytes to
    # survive so that when a downstream handler echoes the value into a
    # file path, ``fd.name`` carries the exact ATK_FLAG_2 token.
    return urlunparse(parts._replace(
        query=urlencode(new_pairs, quote_via=lambda s, safe="", *a, **kw: quote(s, safe=safe + "#"))
    ))


def with_header(
    headers: Mapping[str, str],
    name: str,
    *,
    marker: str = DEFAULT_MARKER,
    mode: str = "suffix",
    separator: str = "",
) -> dict[str, str]:
    """Return new HTTP headers with ``name`` carrying ``marker``."""
    out = dict(headers)
    base = out.get(name, "")
    out[name] = _apply(str(base), marker, mode=mode, separator=separator)
    return out


def with_path_segment(
    url: str,
    *,
    marker: str = DEFAULT_MARKER,
    mode: str = "suffix",
    separator: str = "",
) -> str:
    """Return URL with ``marker`` appended to the path (keeping query/fragment)."""
    from urllib.parse import urlparse, urlunparse

    parts = urlparse(url)
    new_path = _apply(parts.path or "", marker, mode=mode, separator=separator)
    return urlunparse(parts._replace(path=new_path))


def with_filename_suffix(
    path: str,
    *,
    marker: str = DEFAULT_MARKER,
    separator: str = "",
) -> str:
    """Append ``marker`` to a filesystem path.

    Intended for cases where the victim will attempt openat() on this
    path as a side-effect of processing the request. ENOENT is fine —
    the *attempted* syscall is what seeds the anchor.
    """
    return f"{path}{separator}{marker}"


def with_exec_arg(
    argv: Sequence[str],
    *,
    arg_index: int = -1,
    marker: str = DEFAULT_MARKER,
    mode: str = "suffix",
    separator: str = "",
) -> list[str]:
    """Return argv with ``marker`` folded into argv[arg_index]."""
    out = list(argv)
    if not out:
        return out
    idx = arg_index if arg_index >= 0 else len(out) + arg_index
    if 0 <= idx < len(out):
        out[idx] = _apply(str(out[idx]), marker, mode=mode, separator=separator)
    return out


__all__ = [
    "ATK_FLAG_1",
    "ATK_FLAG_2",
    "ATK_FLAG_3",
    "DEFAULT_MARKER",
    "STRATEGY_QUERY",
    "STRATEGY_FORM",
    "STRATEGY_PATH",
    "STRATEGY_HEADER",
    "STRATEGY_FILENAME",
    "STRATEGY_EXEC_ARG",
    "with_form_field",
    "with_query_param",
    "with_header",
    "with_path_segment",
    "with_filename_suffix",
    "with_exec_arg",
]
