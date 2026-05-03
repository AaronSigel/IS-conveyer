"""Typed-model boundary for the reporting package.

The project currently stores report records as dictionaries because existing
CLI and web code already exchange JSON-compatible structures. Model modules
keep that boundary explicit without adding a runtime dependency.
"""
