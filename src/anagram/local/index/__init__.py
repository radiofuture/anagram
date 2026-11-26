"""The local index (spec/index.md): the encrypted store (`store`), sources
and scans (`local`: `LocalIndex`), the job queue (`jobs`), converters
(`convert/`), enrichers (`enrich`), chunks and retrieval (`chunk`,
`retrieve`), spaces, the indexer, and stream checkpoints (`commit`).

Nothing in this package sends index content to the node. Derived meaning
stays in the encrypted index store. Import each module by name; this
package file re-exports nothing.
"""
