"""Checks of the node log answers on this computer (layer L1).

`LogCheck` checks each checkpoint that the node gives (signature, witness
cosignatures, consistency with the last checkpoint that this client saw) and
each inclusion proof, before a client service trusts an answer. It keeps the
last seen checkpoint in the vault. A bad answer raises `LogMisbehaved`.
"""

from __future__ import annotations

from anagram.core.crypto import merkle
from anagram.core.errors import LogMisbehaved
from anagram.identity.app.device import Device
from anagram.proofs.log.checkpoint import Checkpoint, open_checkpoint


class LogCheck:
    def __init__(self, device: Device) -> None:
        self.device = device

    def logged(self, leaf_data: bytes, result: dict) -> Checkpoint:
        """Check the node answer to a submitted entry: the checkpoint, and the
        inclusion of `leaf_data` in it."""
        cp = self.checkpoint(result["checkpoint"])
        path = [bytes.fromhex(h) for h in result["inclusion"]]
        if result["tree_size"] != cp.size or not merkle.verify_inclusion(
            merkle.leaf_hash(leaf_data), result["leaf_index"], cp.size, path, cp.root
        ):
            raise LogMisbehaved("entry is not included in the checkpoint")
        return cp

    def _open(self, note: str):
        trust = self.device.trust()
        try:
            vc = open_checkpoint(note, trust.log_keys, trust.witness_keys)
        except ValueError as exc:
            raise LogMisbehaved(f"bad checkpoint: {exc}") from exc
        if len(vc.cosignatures) < trust.threshold():
            raise LogMisbehaved("checkpoint lacks witness cosignatures")
        return vc.checkpoint

    def checkpoint(self, note: str) -> Checkpoint:
        """Check signature, witness cosignatures, and consistency with the last
        checkpoint that this client saw. Then store it as the last seen."""
        cp = self._open(note)
        vault, node = self.device.vault, self.device.node
        last = vault.log_state(cp.origin)
        if last is not None:
            old_size, old_root, _ = last
            if cp.size < old_size:
                raise LogMisbehaved("log went backwards")
            try:
                proof = [bytes.fromhex(h) for h in node.consistency(old_size, cp.size)]
            except Exception as exc:  # a bad answer of the node in any form
                raise LogMisbehaved(f"node gave no consistency proof: {exc}") from exc
            if not merkle.verify_consistency(
                old_size, cp.size, proof, bytes.fromhex(old_root), cp.root
            ):
                raise LogMisbehaved("log is not consistent with the last seen checkpoint")
        if last is None or cp.size >= last[0]:
            vault.set_log_state(cp.origin, cp.size, cp.root.hex(), note)
        return cp

    def old_checkpoint(self, note: str) -> Checkpoint:
        """Like `checkpoint`, but the checkpoint can be older than the last
        seen one. Then the node must prove that the last seen checkpoint
        extends it."""
        cp = self._open(note)
        last = self.device.vault.log_state(cp.origin)
        if last is None or cp.size >= last[0]:
            return self.checkpoint(note)
        old_size, old_root, _ = last
        proof = [bytes.fromhex(h) for h in self.device.node.consistency(cp.size, old_size)]
        if not merkle.verify_consistency(
            cp.size, old_size, proof, cp.root, bytes.fromhex(old_root)
        ):
            raise LogMisbehaved("old checkpoint is not consistent with the last seen one")
        return cp
