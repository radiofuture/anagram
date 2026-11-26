# Design notes

Short notes on the design patterns that Anagram uses. The spec
([spec/](../../spec/README.md)) says what goes on the wire; these notes say
why the code has its shape.

| Note | Where in the code |
| --- | --- |
| [Confidential operator](confidential-operator.md) | The matching enclave (`anagram.network.matching`) |
| [Disclosure recipient](disclosure-recipient.md) | Model adapters, converters, the MCP gateway |
| [Endorsement chain](endorsement-chain.md) | `anagram.admission` |
| [Group roster with epoch keys](group-roster.md) | The lab unit (`anagram.network.formats.lab`) |
| [Two-party receipt](two-party-receipt.md) | Read records of shared findings |
| [Local UI boundary](local-ui-boundary.md) | `anagram.shell.ui.server` |
| [Live local UI](live-local-ui.md) | `anagram.shell.ui` |
| [OAuth for an app on the person's computer](installed-app-oauth.md) | `anagram.local.sources` |
| [Shared SQLite connection](shared-sqlite-connection.md) | `anagram.core.shared_db` |
