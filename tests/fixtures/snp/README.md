# Real AMD SEV-SNP evidence

Used by `tests/test_enclave_snp.py`. Do not edit these files: they are the
bytes that AMD and a real chip made.

| File | What | Source |
| --- | --- | --- |
| `milan_report.bin` | A version 2 attestation report from a Milan VM (debug on, SMT on, no ID block) | google/go-sev-guest `verify/testdata/attestation.bin` (Apache-2.0, Copyright 2022 Google LLC) |
| `milan_vcek.der` | The VCEK that signed that report | google/go-sev-guest `verify/testdata/vcek.testcer` (Apache-2.0, Copyright 2022 Google LLC) |
| `milan_ark.der`, `milan_ask.der` | The Milan ARK and ASK | AMD KDS, `https://kdsintf.amd.com/vcek/v1/Milan/cert_chain` (fetched 2026-11-27) |
| `genoa_ark.der`, `genoa_ask.der` | The Genoa ARK and ASK | AMD KDS, `https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain` (fetched 2026-11-27) |
| `milan_ark.crl` | The Milan ARK's CRL (next update 2027-01-09) | AMD KDS, `https://kdsintf.amd.com/vcek/v1/Milan/crl` (fetched 2026-11-27) |
| `genoa_ark.crl` | The Genoa ARK's CRL | AMD KDS, `https://kdsintf.amd.com/vlek/v1/Genoa/crl` (fetched 2026-11-27) |

The tests check rule 8 (the evidence step) with these files. They do not
check rule 4 (the CRL's next update), so they do not expire.
