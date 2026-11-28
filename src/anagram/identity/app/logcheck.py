"""Checks of the node log answers on this computer (layer L1).

`LogCheck` checks each checkpoint that the node gives (signature, witness
cosignatures, consistency with the last checkpoint that this client saw) and
each inclusion proof, before a client service trusts an answer. It keeps the
last seen checkpoint in the vault. A bad answer raises `LogMisbehaved`.
"""

from __future__ import annotations

from anagram.core.crypto import merkle
from anagram.core.errors import FormatError, LogMisbehaved
from anagram.core.validate import HEX32, hex_field, int_at_least
from anagram.identity.app.device import Device
from anagram.proofs.log.checkpoint import Checkpoint, open_checkpoint


def _proof_hashes(raw: object, what: str) -> list[bytes]:
    if not isinstance(raw, list):
        raise LogMisbehaved(f"{what} must be a list")
    try:
        return [bytes.fromhex(hex_field(h, HEX32, what)) for h in raw]
    except FormatError as exc:
        raise LogMisbehaved(str(exc)) from exc


class LogCheck:
    def __init__(self, device: Device) -> None:
        self.device = device

    def logged(self, leaf_data: bytes, result: dict) -> Checkpoint:
        """Check the node answer to a submitted entry: the checkpoint, and the
        inclusion of `leaf_data` in it."""
        cp = self.checkpoint(result["checkpoint"])
        try:
            tree_size = int_at_least(result["tree_size"], "tree_size", 0)
            leaf_index = int_at_least(result["leaf_index"], "leaf_index", 0)
        except (KeyError, FormatError) as exc:
            raise LogMisbehaved(f"bad log entry answer: {exc}") from exc
        path = _proof_hashes(result.get("inclusion"), "inclusion")
        if tree_size != cp.size or not merkle.verify_inclusion(
            merkle.leaf_hash(leaf_data), leaf_index, cp.size, path, cp.root
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
                raw_proof = node.consistency(old_size, cp.size)
            except Exception as exc:  # a bad answer of the node in any form
                raise LogMisbehaved(f"node gave no consistency proof: {exc}") from exc
            proof = _proof_hashes(raw_proof, "consistency")
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
        try:
            raw_proof = self.device.node.consistency(cp.size, old_size)
        except Exception as exc:  # a bad answer of the node in any form
            raise LogMisbehaved(f"node gave no consistency proof: {exc}") from exc
        proof = _proof_hashes(raw_proof, "consistency")
        if not merkle.verify_consistency(
            cp.size, old_size, proof, cp.root, bytes.fromhex(old_root)
        ):
            raise LogMisbehaved("old checkpoint is not consistent with the last seen one")
        return cp
