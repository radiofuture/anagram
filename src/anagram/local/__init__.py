"""Local node (layer L2): the data of one person on one
computer. Nothing here sends plaintext to the node.

- `sources/`: connectors, OAuth, credentials, the sync engine, source state.
- `index/`: the encrypted index store, jobs, converters, enrichers, chunks,
  retrieval, spaces, the indexer, stream checkpoints.
- `understanding/`: kinds, the `understand` stage, links, proposals, digest,
  ask, titles, chips, drafts, the vocabulary.
- `vault.py`, `findings.py`, `localdb.py`: the local vault and own proofs.
- `ports.py`: `LabContext`, `Committer`, `LocalClient` (the composition root
  gives them).
"""
