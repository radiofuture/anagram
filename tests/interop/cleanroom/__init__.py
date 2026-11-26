"""A clean-room app and node client for the Anagram matching enclave.

The code in this package was written only from `spec/` (pack.md,
enclave-messages.md, network.md, enclave-trust.md, matching.md,
log.md, formats.md sections 2 and 3, identity.md section 1) and its vectors.
It imports nothing from `anagram`. It uses only third-party libraries
(`cryptography`, `biscuit-python`). Its purpose is to show that the specs
alone are enough to build a client that interoperates with the reference
enclave, and to find the places where they are not.

Each place where the spec was not enough has a `SPEC GAP` comment with the
reading that this code chose.
"""
