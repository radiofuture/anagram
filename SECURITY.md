# Security policy

## Report a vulnerability

Report it privately through GitHub: open the repository's **Security** tab,
then **Report a vulnerability** (a private security advisory). Only the
maintainers can see the report.

Do not open a public issue, pull request or discussion for a vulnerability.

Tell us:

- what the problem is and what an attacker can do with it,
- the steps or code to show it,
- the version or commit, and the profile (simulated or other),
- if you want credit, and the name to use.

## What we promise

- We reply to say that we received your report within 3 working days.
- We send our first assessment within 10 working days.
- We keep you informed while we fix it, and we agree a publication date
  with you.
- We give you credit in the advisory and the changelog, if you want it.
- We do not take legal action against good-faith research that follows this
  policy: no access to other people's data, no service disruption, and
  private disclosure.

## Scope

In scope: the code in this repository and the protocol in `spec/`, for
example:

- the proof formats, the log and the verifier (a false proof that verifies),
- the local UI server (loopback, token, CSRF and DNS rebinding checks),
- the vault, key storage and recovery (guardians, recovery kit),
- the community node, member credentials and admission,
- the matching protocol and the enclave messages,
- leaks of private data to the node, the log or the logs of a process.

Out of scope:

- confidentiality of the matching enclave from its operator (see below),
- attacks that need full control of the person's own computer,
- denial of service by volume,
- problems in dependencies with no effect on Anagram (report them upstream).

## The matching enclave runs in simulated mode

This build runs the matching enclave only in the **simulated profile**. The
enclave is an ordinary process, and its attestation is a signature by a
development key. **It gives no confidentiality from the operator of the
host.** Real protection needs the hardware (TEE) profile, which is not in
this build yet. Until it ships, do not use a simulated network for real
research plans. See [docs/enclave.md](docs/enclave.md).

Reports about the protocol design of the TEE profile are welcome, but a
report that the simulated enclave is not confidential is a known limit, not
a vulnerability.

## Supported versions

Anagram has no stable release yet. We fix security problems on the main
development branch only.
