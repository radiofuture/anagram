# Real Intel TDX evidence

Used by `tests/test_enclave_tdx.py`. Do not edit these files: they are the
bytes that Intel and real platforms made. The collateral is signed over its
exact bytes, so even a changed space breaks it.

| File | What | Source |
| --- | --- | --- |
| `spr_quote.dat` | A TDX quote, version 4, from a Sapphire Rapids platform (FMSPC `50806f000000`), followed by go-tdx-guest's line `extra bytes(only for testing purpose)` | google/go-tdx-guest `testing/testdata/tdx_prod_quote_SPR_E4.dat` (Apache-2.0, Copyright 2023 Google LLC) |
| `cos_quote.dat` | A TDX quote, version 4, from a Container-Optimized OS VM (FMSPC `00806f050000`), zero padded to 8000 bytes | google/go-tdx-guest `testing/testdata/ccel/cos-113-tdx-quote.dat` (Apache-2.0, Copyright 2023 Google LLC) |
| `intel_root.der` | The Intel SGX Root CA | `https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.cer` (fetched 2026-11-27) |
| `tcb_info_50806f000000.json`, `tcb_info_00806f050000.json` | TDX TCB Info for each FMSPC (next update 2026-12-27) | Intel PCS, `https://api.trustedservices.intel.com/tdx/certification/v4/tcb?fmspc=<FMSPC>` (fetched 2026-11-27) |
| `qe_identity.json` | TD QE Identity | Intel PCS, `https://api.trustedservices.intel.com/tdx/certification/v4/qe/identity` (fetched 2026-11-27) |
| `tcb_signing.der` | The Intel SGX TCB Signing certificate (the first certificate of the `TCB-Info-Issuer-Chain` header of the TCB Info response) | Intel PCS (fetched 2026-11-27) |
| `pck_platform.crl` | The PCK Platform CA's CRL | Intel PCS, `https://api.trustedservices.intel.com/sgx/certification/v4/pckcrl?ca=platform&encoding=der` (fetched 2026-11-27) |
| `root.crl` | The Intel SGX Root CA's CRL | `https://certificates.trustedservices.intel.com/IntelSGXRootCA.der` (fetched 2026-11-27) |

The tests remove what follows each quote (`trimmed`); the
verifier refuses any byte after the quote's declared length. The tests
check rule 8 (the evidence step) with these files. They do not check
rule 4 (the next updates), so they do not expire.
