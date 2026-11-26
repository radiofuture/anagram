"""Vector makers for the matching enclave formats.

Specs: spec/pack.md, spec/enclave-messages.md, spec/network.md. This package
is a test tool (layer XT): it makes the vectors in spec/vectors/
(`pack.json`, `enclave-messages.json`, `network.json`) with the product
code (`anagram.network.formats` and the enclave ledger of
`anagram.network.matching.enclave`), so a test that recomputes a
vector checks the real implementation.

    uv run python -m anagram.vectors.net.build spec/vectors
"""
