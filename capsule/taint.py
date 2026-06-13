"""Content-based taint / provenance store.

THE KEY PROPERTY: enforcement is content-based, not declaration-based. When
read_file returns content, we register the *actual text* (plus a sha256 and a
set of k-gram shingle hashes). When an outbound/write tool is invoked, we scan
its argument values for overlap with the store. A malicious caller that pastes a
secret straight into a PR body — declaring no source_refs — is still caught,
because matching is on content, not on a cooperative declaration.

Milestone E — re-encoding resistance. Naive content matching is defeated by
transforming the data before it reaches the outbound tool. This module now sees
through the cheap, common transforms an exfil script actually reaches for:

  - case / whitespace changes        -> normalization (casefold + ws-collapse)
  - base64 / base64url               -> speculative decode of encoded-looking runs
  - hex                              -> speculative decode
  - URL percent-encoding             -> unquote
  - gzip-then-base64                 -> decode + bounded gunzip
  - split across multiple calls      -> bounded per-session reassembly buffer
                                        ("send half now, half later")

Each outbound value is expanded into a small set of *candidate views* (the raw
value plus whatever the decoders recover); every view is matched through the same
substring + shingle logic, against a normalized copy of the stored content. A
match records which `transform` exposed it, so the audit shows e.g.
`untrusted_repo_content:content_001:substring:base64`.

Honest limitation (state in README/threat-model): this is minimal provenance by
content matching, NOT full information-flow control. It is still evadable by
*lossy or keyed* transforms — encryption with an attacker-held key, semantic
paraphrase ("the key starts with AKIA…"), or steganography — because the bytes no
longer derive recoverably from the secret. Milestone E shrinks the evasion
surface from "any transform" to "transforms that destroy recoverability"; it does
not eliminate it. Acknowledged future work.

Lifecycle: per-session, in-process. Optionally mirrored to demo/taint_store.jsonl
for the demo. Cleared on restart. No cross-session persistence in v0.1.
"""

from __future__ import annotations

import base64
import binascii
import gzip
import hashlib
import io
import re
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import unquote

from capsule.models import TaintLabel

# k for word-level shingles. Small enough to catch partial pastes / light edits,
# large enough to avoid matching incidental common phrases.
SHINGLE_K = 5
# Minimum shingle overlap (count) to call it a fuzzy match when there is no
# exact substring hit.
SHINGLE_THRESHOLD = 2
# A stored span shorter than this is only matched exactly (avoids flagging tiny
# common tokens via substring).
MIN_SUBSTRING_LEN = 12

_WS_RE = re.compile(r"\s+")
# Shingle tokens are alphanumeric runs: dropping boundary punctuation means a
# secret word stays the same token whether it is bare (`rotate`) or wrapped by
# the surrounding command (`'rotate`, `rotate,`), so k-grams survive shell
# quoting and light reformatting. Substring matching, by contrast, runs on the
# punctuation-preserving normalized form so secrets containing `/ + =` (e.g. an
# AWS key) still match verbatim.
_WORD_RE = re.compile(r"[^\W_]+", re.UNICODE)

# ---- decode bounds (keep speculative decoding cheap and low-false-positive) ----
# Only attempt to decode encoded-looking runs at least this long: short runs are
# common in benign text and decode to noise.
_MIN_B64_RUN = 20
_MIN_HEX_RUN = 24  # even length; 12 bytes
# Cap the bytes produced by any single decode (incl. gunzip) so a crafted input
# can't blow up memory; 256 KiB is far above any real secret snippet.
_MAX_DECODED_BYTES = 256 * 1024
# A decoded view is only used if it is "mostly text" — guards against feeding
# binary noise (which never matches anyway) into the matchers.
_MIN_PRINTABLE_RATIO = 0.8

# Encoded-looking runs. base64 alphabet incl. url-safe (-_) and padding (=).
_B64_RUN_RE = re.compile(rf"[A-Za-z0-9+/_-]{{{_MIN_B64_RUN},}}={{0,2}}")
_HEX_RUN_RE = re.compile(rf"[0-9a-fA-F]{{{_MIN_HEX_RUN},}}")
_GZIP_MAGIC = b"\x1f\x8b"

# ---- cross-call reassembly bounds ----
# Per-session ring of recent outbound candidate strings. Bounded so a long-lived
# session can't grow without limit; chunked exfil is reassembled from these.
_BUFFER_MAXLEN = 32
_BUFFER_MAX_CHARS = 64 * 1024


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _normalize(text: str) -> str:
    """Casefold + collapse whitespace.

    Defeats case-flip and whitespace/newline reshuffling without harming
    precision (punctuation is preserved — secrets contain `/`, `+`, `=`). Applied
    symmetrically to stored content and to every candidate view before matching.
    """
    return _WS_RE.sub(" ", text.casefold()).strip()


def shingles(text: str, k: int = SHINGLE_K) -> set[str]:
    """Hashed k-gram word shingles of `text`."""
    words = _WORD_RE.findall(text)
    if len(words) < k:
        # Short content: one shingle of the whole thing.
        if not words:
            return set()
        return {hashlib.sha1(" ".join(words).encode()).hexdigest()}
    out: set[str] = set()
    for i in range(len(words) - k + 1):
        gram = " ".join(words[i : i + k])
        out.add(hashlib.sha1(gram.encode()).hexdigest())
    return out


def _printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    try:
        text = b.decode("utf-8")
    except UnicodeDecodeError:
        return 0.0
    if not text:
        return 0.0
    printable = sum(c.isprintable() or c in "\t\n\r " for c in text)
    return printable / len(text)


def _maybe_text(b: bytes) -> str | None:
    """Return decoded bytes as text iff they look like text, else None."""
    if not b or len(b) > _MAX_DECODED_BYTES:
        return None
    if _printable_ratio(b) < _MIN_PRINTABLE_RATIO:
        return None
    return b.decode("utf-8", errors="replace")


def _try_base64(run: str) -> bytes | None:
    # Normalize url-safe alphabet and fix padding before decoding.
    s = run.rstrip("=").replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    try:
        return base64.b64decode(s, validate=True)
    except (binascii.Error, ValueError):
        return None


def _try_gunzip(b: bytes) -> bytes | None:
    if not b.startswith(_GZIP_MAGIC):
        return None
    try:
        # Stream the decompression and read at most one byte past the cap, so a
        # decompression bomb can never materialize its full output: gzip.decompress
        # would inflate the whole stream before any slice could apply. Reading
        # cap+1 lets `_maybe_text` reject anything over the cap.
        with gzip.GzipFile(fileobj=io.BytesIO(b)) as gz:
            return gz.read(_MAX_DECODED_BYTES + 1)
    except (OSError, EOFError, ValueError):
        return None


def _decode_views(value: str) -> list[tuple[str, str]]:
    """Recover candidate plaintext views from `value` via cheap, common decoders.

    Returns (transform_label, decoded_text) pairs. Bounded in count and size; a
    decoded run is kept only when it looks like text (see `_maybe_text`), which
    both limits false positives and avoids feeding binary noise to the matchers.
    """
    views: list[tuple[str, str]] = []

    # URL percent-encoding: a single whole-value unquote is enough.
    if "%" in value:
        unq = unquote(value)
        if unq != value:
            views.append(("url", unq))

    seen: set[str] = set()
    for run in _B64_RUN_RE.findall(value):
        raw = _try_base64(run)
        if raw is None:
            continue
        gunzipped = _try_gunzip(raw)
        if gunzipped is not None:
            txt = _maybe_text(gunzipped)
            if txt and txt not in seen:
                seen.add(txt)
                views.append(("gzip+base64", txt))
            continue
        txt = _maybe_text(raw)
        if txt and txt not in seen:
            seen.add(txt)
            views.append(("base64", txt))

    for run in _HEX_RUN_RE.findall(value):
        if len(run) % 2:
            continue
        try:
            raw = bytes.fromhex(run)
        except ValueError:
            continue
        txt = _maybe_text(raw)
        if txt and txt not in seen:
            seen.add(txt)
            views.append(("hex", txt))

    return views


@dataclass
class TaintEntry:
    content_ref: str
    text: str
    label: TaintLabel
    shingle_set: set[str] = field(default_factory=set)
    # Normalized projections, computed once at register time (Milestone E):
    # matching compares normalized-view-vs-normalized-store so case/whitespace
    # edits and decoded payloads line up.
    norm_text: str = ""
    norm_shingles: set[str] = field(default_factory=set)


@dataclass
class TaintMatch:
    content_ref: str
    kind: str  # "substring" | "shingle"
    taint: str
    detail: str
    transform: str = "raw"  # "raw" | "base64" | "hex" | "url" | "gzip+base64" | "chunked"


class TaintStore:
    def __init__(self, mirror_path: str | Path | None = None):
        self._entries: dict[str, TaintEntry] = {}
        self._counter = 0
        self.mirror_path = Path(mirror_path) if mirror_path else None
        # Per-session reassembly buffer for cross-call (chunked) exfil.
        self._outbound: deque[str] = deque(maxlen=_BUFFER_MAXLEN)

    def _next_ref(self, prefix: str = "content") -> str:
        self._counter += 1
        return f"{prefix}_{self._counter:03d}"

    def register(
        self,
        text: str,
        *,
        source_type: str = "repo_file",
        path: str | None = None,
        taint: str = "untrusted_repo_content",
        content_ref: str | None = None,
    ) -> TaintLabel:
        ref = content_ref or self._next_ref()
        sh = shingles(text)
        label = TaintLabel(
            content_ref=ref,
            source_type=source_type,
            path=path,
            taint=taint,
            trusted=False,
            content_sha256=sha256_hex(text),
            shingles=sorted(sh),
        )
        norm = _normalize(text)
        self._entries[ref] = TaintEntry(
            ref, text, label, sh, norm_text=norm, norm_shingles=shingles(norm)
        )
        self._mirror(label)
        return label

    # -- matching -----------------------------------------------------------
    def _match_one(self, entry: TaintEntry, norm_value: str, transform: str) -> TaintMatch | None:
        """Substring + shingle check of one already-normalized candidate."""
        if not norm_value:
            return None
        stored = entry.norm_text
        # Exact / substring of a meaningful span, in EITHER direction: the
        # outbound arg may contain the stored secret, or be a verbatim fragment
        # of it. Both are exfil.
        shorter, longer = sorted((stored, norm_value), key=len)
        if len(shorter) >= MIN_SUBSTRING_LEN and shorter in longer:
            return TaintMatch(
                content_ref=entry.content_ref,
                kind="substring",
                taint=entry.label.taint,
                detail=f"{len(shorter)} chars overlap with {entry.content_ref} verbatim",
                transform=transform,
            )
        overlap = len(entry.norm_shingles & shingles(norm_value))
        if overlap >= SHINGLE_THRESHOLD:
            return TaintMatch(
                content_ref=entry.content_ref,
                kind="shingle",
                taint=entry.label.taint,
                detail=f"{overlap} shingle(s) overlap with {entry.content_ref}",
                transform=transform,
            )
        return None

    def match(self, value: str) -> list[TaintMatch]:
        """Return taint matches between `value` and any stored content.

        Pure (no session state): expands `value` into candidate views (raw +
        decoded) and matches each through `_match_one`. At most one match per
        stored entry — the first transform that exposes it wins.
        """
        if not value:
            return []
        views = [("raw", value), *_decode_views(value)]
        norm_views = [(t, _normalize(text)) for t, text in views]
        matches: list[TaintMatch] = []
        for entry in self._entries.values():
            for transform, norm_text in norm_views:
                m = self._match_one(entry, norm_text, transform)
                if m is not None:
                    matches.append(m)
                    break
        return matches

    def scan_outbound(self, values: list[str]) -> list[TaintMatch]:
        """Match outbound `values` AND fold them into the cross-call buffer.

        Stateful — call exactly once per outbound tool invocation. Returns
        per-value matches plus any *chunked* match recovered by reassembling the
        recent buffer (catches a secret split across multiple calls).

        Only values that did NOT match on their own are buffered: the buffer
        exists to accumulate sub-threshold *fragments*. Buffering a value that
        already matched directly would let a later clean call rediscover that full
        secret as a (false) chunked hit — escalating innocent calls until the
        entry evicts — so a direct hit is never remembered.
        """
        direct: list[TaintMatch] = []
        for value in values:
            value_matches = self.match(value)
            direct.extend(value_matches)
            if not value_matches:
                for _, text in [("raw", value), *_decode_views(value)]:
                    self._remember(_normalize(text))

        matched_refs = {m.content_ref for m in direct}
        chunked = [m for m in self._match_accumulated() if m.content_ref not in matched_refs]
        return direct + chunked

    def _remember(self, norm_text: str) -> None:
        if norm_text:
            self._outbound.append(norm_text)

    def _match_accumulated(self) -> list[TaintMatch]:
        """Reassemble the buffer and match against the store.

        Two complementary signals, both bounded by the buffer size:

          - union of the buffered fragments' shingles vs the stored shingles.
            A fragment carrying >=5 consecutive secret words contributes its real
            k-gram even when wrapped in command noise (`curl -d <frag>`), so two
            such fragments union to >=2 and trip the threshold — the robust path
            for chunked exfil. (scan_outbound only reports chunked hits for refs
            no single call matched, so the contributing shingles necessarily come
            from >=2 calls; one call with >=2 shingles would have matched
            directly.)
          - substring of the in-order concatenation, which additionally catches a
            contiguous secret split mid-window when the chunks carry no noise.
        """
        if len(self._outbound) < 2:
            return []
        union: set[str] = set()
        for frag in self._outbound:
            union |= shingles(frag)
        joined = " ".join(self._outbound)[:_BUFFER_MAX_CHARS]
        out: list[TaintMatch] = []
        for entry in self._entries.values():
            if len(entry.norm_text) >= MIN_SUBSTRING_LEN and entry.norm_text in joined:
                out.append(
                    TaintMatch(
                        content_ref=entry.content_ref,
                        kind="substring",
                        taint=entry.label.taint,
                        detail=f"{entry.content_ref} reassembled verbatim across calls",
                        transform="chunked",
                    )
                )
                continue
            overlap = len(entry.norm_shingles & union)
            if overlap >= SHINGLE_THRESHOLD:
                out.append(
                    TaintMatch(
                        content_ref=entry.content_ref,
                        kind="shingle",
                        taint=entry.label.taint,
                        detail=f"{overlap} shingle(s) of {entry.content_ref} across "
                        f"{len(self._outbound)} buffered call(s)",
                        transform="chunked",
                    )
                )
        return out

    def is_tainted(self, value: str) -> bool:
        return bool(self.match(value))

    def clear(self) -> None:
        self._entries.clear()
        self._counter = 0
        self._outbound.clear()

    def _mirror(self, label: TaintLabel) -> None:
        if not self.mirror_path:
            return
        self.mirror_path.parent.mkdir(parents=True, exist_ok=True)
        with self.mirror_path.open("a") as fh:
            fh.write(label.model_dump_json() + "\n")
