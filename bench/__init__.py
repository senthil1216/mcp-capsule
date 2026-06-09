"""Capsule benchmark harness.

Measures the gateway against an attack corpus, apples-to-apples: unsafe and safe
modes run against the SAME disposable environment, with honeytokens planted at
the real canonical secret paths inside a throwaway HOME (never the developer's
real ~/.ssh). Exfil is measured via a local recording sink, not asserted.
"""
