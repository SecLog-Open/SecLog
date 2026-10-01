# Auxiliary annotation context

This directory contains the complete vulnerability-facts seed used after
window selection for semantic disambiguation during annotation and review.
It includes normalized context, raw source snapshots, and structured source
references.

It is not primary stage evidence, must not determine a stage label by itself,
and must never be included in model-facing prediction input. Concrete stage
judgments must remain grounded in the visible log window.

`vulnerability_facts_seed/raw_sources/` documents the sources of the auxiliary
facts. Neither raw sources nor normalized context is model-visible
evidence or a substitute for the selected log window.
