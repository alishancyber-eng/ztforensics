"""
Blockchain module for ZTForensics API Gateway.
Provides a tamper-evident, in-memory hash chain for access log entries.
"""
import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


class BlockchainManager:
    """Manages an in-memory blockchain of access log entries."""

    def __init__(self) -> None:
        self._chain: list[dict[str, Any]] = []
        self._create_genesis_block()
        logger.info("BlockchainManager initialised with genesis block.")

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _create_genesis_block(self) -> None:
        """Add the immutable genesis block to the chain."""
        genesis: dict[str, Any] = {
            "index": 0,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": {"genesis": True},
            "previous_hash": "0" * 64,
        }
        genesis["hash"] = self.create_hash(genesis)
        self._chain.append(genesis)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def create_hash(data: dict[str, Any]) -> str:
        """Return the SHA-256 hex digest of *data* serialised as JSON.

        Args:
            data: Arbitrary dictionary to hash.

        Returns:
            Lowercase hex SHA-256 digest string.
        """
        serialised = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(serialised.encode()).hexdigest()

    def add_block(self, log_entry: dict[str, Any]) -> str:
        """Append a new block containing *log_entry* to the chain.

        Args:
            log_entry: The access log data to embed in the block.

        Returns:
            The SHA-256 hash of the newly created block.
        """
        previous_block = self._chain[-1]
        new_block: dict[str, Any] = {
            "index": len(self._chain),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "data": log_entry,
            "previous_hash": previous_block["hash"],
        }
        new_block["hash"] = self.create_hash(new_block)
        self._chain.append(new_block)
        logger.debug("Block %d added; hash=%s", new_block["index"], new_block["hash"])
        return new_block["hash"]

    def verify_chain(self) -> dict[str, Any]:
        """Verify the integrity of the entire chain.

        Returns:
            A dict with keys ``valid`` (bool), ``total_blocks`` (int),
            and ``verified_blocks`` (int).
        """
        verified = 0
        for i in range(1, len(self._chain)):
            current = self._chain[i]
            previous = self._chain[i - 1]

            # Recompute hash (exclude the stored hash itself)
            block_without_hash = {k: v for k, v in current.items() if k != "hash"}
            recomputed = self.create_hash(block_without_hash)

            if current["hash"] != recomputed:
                logger.warning("Block %d has an invalid hash.", i)
                break
            if current["previous_hash"] != previous["hash"]:
                logger.warning("Block %d has a broken previous_hash link.", i)
                break
            verified += 1

        total = len(self._chain) - 1  # exclude genesis
        valid = verified == total
        logger.info("Chain verification: valid=%s (%d/%d)", valid, verified, total)
        return {"valid": valid, "total_blocks": total, "verified_blocks": verified}

    def get_chain_stats(self) -> dict[str, Any]:
        """Return statistics about the current chain.

        Returns:
            Dict with ``total_blocks``, ``chain_length``,
            ``genesis_hash``, and ``latest_hash``.
        """
        return {
            "total_blocks": len(self._chain) - 1,
            "chain_length": len(self._chain),
            "genesis_hash": self._chain[0]["hash"],
            "latest_hash": self._chain[-1]["hash"],
        }
