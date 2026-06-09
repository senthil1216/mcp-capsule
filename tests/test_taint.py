"""Taint store tests (the content-based-match property)."""

from capsule.taint import TaintStore


def test_register_returns_label_with_hash_and_shingles():
    store = TaintStore()
    label = store.register("the quick brown fox jumps over the lazy dog", path="README.md")
    assert label.content_ref.startswith("content_")
    assert label.content_sha256
    assert label.shingles
    assert label.taint == "untrusted_repo_content"


def test_exact_substring_match():
    store = TaintStore()
    store.register("SUPER-SECRET-VALUE-1234567890")
    # Pasted verbatim into an outbound arg, with NO declared source_ref.
    assert store.is_tainted("please use SUPER-SECRET-VALUE-1234567890 in the PR")


def test_shingle_fuzzy_match_survives_light_edits():
    store = TaintStore()
    store.register(
        "alpha beta gamma delta epsilon zeta eta theta iota kappa lambda mu"
    )
    # Same long phrase with a couple words changed -> shingle overlap still fires.
    edited = "XX beta gamma delta epsilon zeta eta theta iota kappa lambda YY"
    assert store.is_tainted(edited)


def test_unrelated_text_not_tainted():
    store = TaintStore()
    store.register("AKIA-style-secret-abcdefghijklmnop")
    assert not store.is_tainted("a totally unrelated short note")


def test_clear():
    store = TaintStore()
    store.register("SUPER-SECRET-VALUE-1234567890")
    store.clear()
    assert not store.is_tainted("SUPER-SECRET-VALUE-1234567890")
