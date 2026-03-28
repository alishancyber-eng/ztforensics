"""
Tamper-detection and blockchain integrity tests for ZTForensics.
10 tests covering hash chain creation, verification, tamper detection,
broken previous_hash links, and multi-block integrity.
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'api_gateway'))
os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")

import pytest
from blockchain import BlockchainManager


class TestBlockchainChainCreation:
    """Tests for hash chain creation and structure."""

    def test_new_chain_has_genesis_block(self):
        bm = BlockchainManager()
        assert len(bm._chain) == 1
        assert bm._chain[0]["previous_hash"] == "0" * 64

    def test_block_indices_sequential(self):
        bm = BlockchainManager()
        bm.add_block({"user": "alice", "action": "READ"})
        bm.add_block({"user": "bob", "action": "WRITE"})
        assert bm._chain[0]["index"] == 0
        assert bm._chain[1]["index"] == 1
        assert bm._chain[2]["index"] == 2

    def test_each_block_links_to_previous(self):
        bm = BlockchainManager()
        h1 = bm.add_block({"n": 1})
        h2 = bm.add_block({"n": 2})
        assert bm._chain[2]["previous_hash"] == bm._chain[1]["hash"]
        assert bm._chain[1]["previous_hash"] == bm._chain[0]["hash"]

    def test_hash_collision_prevention(self):
        """Two different records must produce different hashes."""
        bm = BlockchainManager()
        h1 = bm.add_block({"user": "alice", "resource": "docs"})
        h2 = bm.add_block({"user": "alice", "resource": "admin"})
        assert h1 != h2


class TestBlockchainVerification:
    """Tests for chain verification and tamper detection."""

    def test_verify_chain_valid_after_adds(self):
        bm = BlockchainManager()
        bm.add_block({"x": 1})
        bm.add_block({"x": 2})
        result = bm.verify_chain()
        assert result["valid"] is True
        assert result["verified_blocks"] == 2

    def test_verify_detects_tampered_data(self):
        """Changing a block's data invalidates its hash."""
        bm = BlockchainManager()
        bm.add_block({"user": "alice"})
        bm._chain[1]["data"]["user"] = "eve"          # tamper
        result = bm.verify_chain()
        assert result["valid"] is False

    def test_verify_detects_broken_previous_hash_link(self):
        """Changing previous_hash of a block breaks the chain."""
        bm = BlockchainManager()
        bm.add_block({"a": 1})
        bm.add_block({"b": 2})
        # Break the previous_hash link on block 2 while keeping hash intact
        bm._chain[2]["previous_hash"] = "0" * 64
        result = bm.verify_chain()
        assert result["valid"] is False

    def test_verify_empty_chain_is_valid(self):
        """A chain with only genesis block should be valid."""
        bm = BlockchainManager()
        result = bm.verify_chain()
        assert result["valid"] is True
        assert result["total_blocks"] == 0

    def test_missing_record_detection(self):
        """Removing a block from the chain should break verification."""
        bm = BlockchainManager()
        bm.add_block({"r": 1})
        bm.add_block({"r": 2})
        bm.add_block({"r": 3})
        # Remove block at index 2 (middle block)
        bm._chain.pop(2)
        result = bm.verify_chain()
        assert result["valid"] is False

    def test_multiple_tamper_detection(self):
        """Tamper with hash on first non-genesis block."""
        bm = BlockchainManager()
        bm.add_block({"event": "login"})
        bm.add_block({"event": "access"})
        bm._chain[1]["hash"] = "a" * 64   # tamper block 1 hash
        result = bm.verify_chain()
        assert result["valid"] is False
