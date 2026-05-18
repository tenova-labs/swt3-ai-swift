"""SWT3 AI Witness SDK -- Merkle Tree + Accumulator Tests.

10 tests: primitives, root determinism, proof verification,
accumulator lifecycle, config extraction, edge cases.
"""

import json
import os
import tempfile

import pytest

from swt3_ai.merkle import (
    hash_leaf,
    hash_node,
    get_merkle_root,
    get_merkle_proof,
    verify_merkle_proof,
    MerkleAccumulator,
)


class TestMerklePrimitives:
    def test_hash_leaf_domain_separator(self):
        h = hash_leaf("abc123def456")
        assert len(h) == 64
        assert hash_leaf("xyz") != h

    def test_hash_node_domain_separator(self):
        h = hash_node("aaa", "bbb")
        assert len(h) == 64
        # leaf and node of same content differ (domain separation)
        assert hash_leaf("aaa") != hash_node("aaa", "")

    def test_merkle_root_deterministic_regardless_of_order(self):
        fps = ["fp_c", "fp_a", "fp_b", "fp_d"]
        root1 = get_merkle_root(fps)
        root2 = get_merkle_root(["fp_b", "fp_d", "fp_a", "fp_c"])
        assert root1 == root2
        assert len(root1) == 64

    def test_merkle_root_empty_input(self):
        assert get_merkle_root([]) == ""

    def test_merkle_root_single_fingerprint(self):
        root = get_merkle_root(["solo"])
        assert root == hash_leaf("solo")


class TestMerkleProofs:
    def test_generates_and_verifies_valid_proof(self):
        fps = ["fp_1", "fp_2", "fp_3", "fp_4", "fp_5"]
        proof = get_merkle_proof(fps, "fp_3")
        assert proof is not None
        assert proof.fingerprint == "fp_3"
        assert proof.root == get_merkle_root(fps)
        assert verify_merkle_proof("fp_3", proof) is True

    def test_returns_none_for_missing_fingerprint(self):
        assert get_merkle_proof(["a", "b"], "c") is None
        assert get_merkle_proof([], "a") is None

    def test_rejects_tampered_proof(self):
        fps = ["fp_1", "fp_2", "fp_3"]
        proof = get_merkle_proof(fps, "fp_1")
        assert proof is not None
        from swt3_ai.merkle import MerkleProof
        tampered = MerkleProof(
            fingerprint=proof.fingerprint,
            leaf_hash=proof.leaf_hash,
            root="0" * 64,
            steps=proof.steps,
        )
        assert verify_merkle_proof("fp_1", tampered) is False


class TestMerkleAccumulator:
    def test_computes_session_root_and_persists(self):
        with tempfile.TemporaryDirectory() as d:
            acc = MerkleAccumulator(persist_dir=d, tenant_id="TEST")
            acc.add("fp_a")
            acc.add("fp_b")
            assert acc.pending == 2

            result = acc.flush()
            assert result is not None
            assert result.root == get_merkle_root(["fp_a", "fp_b"])
            assert result.count == 2
            assert acc.pending == 0
            assert len(acc.roots) == 1

            # Verify JSONL persistence
            jsonl_path = os.path.join(d, "TEST.roots.jsonl")
            assert os.path.isfile(jsonl_path)
            with open(jsonl_path) as f:
                lines = [l for l in f.read().strip().split("\n") if l]
            assert len(lines) == 1
            persisted = json.loads(lines[0])
            assert persisted["root"] == result.root

    def test_empty_flush_returns_none(self):
        acc = MerkleAccumulator()
        assert acc.flush() is None

    def test_generates_proofs_from_sessions(self):
        acc = MerkleAccumulator()
        acc.add_many(["fp_x", "fp_y", "fp_z"])
        acc.flush()

        proof = acc.prove("fp_y")
        assert proof is not None
        assert verify_merkle_proof("fp_y", proof) is True

        assert acc.prove("fp_missing") is None

    def test_reset_clears_pending_keeps_history(self):
        acc = MerkleAccumulator()
        acc.add("fp_1")
        acc.flush()
        acc.add("fp_2")
        acc.reset()
        assert acc.pending == 0
        assert len(acc.roots) == 1

        acc.clear()
        assert len(acc.roots) == 0
