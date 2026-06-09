"""Content-based taint / provenance store.

THE KEY PROPERTY: enforcement is content-based, not declaration-based. When
read_file returns content, we register the *actual text* (plus a sha256 and a
set of k-gram shingle hashes). When an outbound/write tool is invoked, we scan
its argument values for overlap with the store. A malicious caller that pastes a
secret straight into a PR body — declaring no source_refs — is still caught,
because matching is on content, not on a cooperative declaration.

Honest limitation (state in README/threat-model): this is minimal provenance by
content matching, NOT full information-flow control. It can be evaded by
re-encoding/transforming the data (base64, char substitution) before it reaches
the outbound tool. That is acknowledged future work.

Lifecycle: per-session, in-process. Optionally mirrored to demo/taint_store.jsonl
for the demo. Cleared on restart. No cross-session persistence in v0.1.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path

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

_WORD_RE = re.compile(r"\S+")


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


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


@dataclass
class TaintEntry:
    content_ref: str
    text: str
    label: TaintLabel
    shingle_set: set[str] = field(default_factory=set)


@dataclass
class TaintMatch:
    content_ref: str
    kind: str  # "substring" | "shingle"
    taint: str
    detail: str


class TaintStore:
    def __init__(self, mirror_path: str | Path | None = None):
        self._entries: dict[str, TaintEntry] = {}
        self._counter = 0
        self.mirror_path = Path(mirror_path) if mirror_path else None

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
        self._entries[ref] = TaintEntry(ref, text, label, sh)
        self._mirror(label)
        return label

    def match(self, value: str) -> list[TaintMatch]:
        """Return taint matches between `value` and any stored content."""
        if not value:
            return []
        matches: list[TaintMatch] = []
        value_shingles = shingles(value)
        value_stripped = value.strip()
        for entry in self._entries.values():
            # Exact / substring of a meaningful span, in EITHER direction:
            # the outbound arg may contain the stored secret (stored in value),
            # or be a verbatim fragment of it (value in stored). Both are exfil.
            stored = entry.text.strip()
            shorter = stored if len(stored) <= len(value_stripped) else value_stripped
            longer = value_stripped if shorter is stored else stored
            if len(shorter) >= MIN_SUBSTRING_LEN and shorter in longer:
                matches.append(
                    TaintMatch(
                        content_ref=entry.content_ref,
                        kind="substring",
                        taint=entry.label.taint,
                        detail=f"{len(shorter)} chars overlap with {entry.content_ref} verbatim",
                    )
                )
                continue
            # Fuzzy: shingle overlap (catches partial paste / light edits).
            overlap = len(entry.shingle_set & value_shingles)
            if overlap >= SHINGLE_THRESHOLD:
                matches.append(
                    TaintMatch(
                        content_ref=entry.content_ref,
                        kind="shingle",
                        taint=entry.label.taint,
                        detail=f"{overlap} shingle(s) overlap with {entry.content_ref}",
                    )
                )
        return matches

    def is_tainted(self, value: str) -> bool:
        return bool(self.match(value))

    def clear(self) -> None:
        self._entries.clear()
        self._counter = 0

    def _mirror(self, label: TaintLabel) -> None:
        if not self.mirror_path:
            return
        self.mirror_path.parent.mkdir(parents=True, exist_ok=True)
        with self.mirror_path.open("a") as fh:
            fh.write(label.model_dump_json() + "\n")
