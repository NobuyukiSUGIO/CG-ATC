"""Merkle tree over audit events (paper §III-F).

    root_i^t = MerkleRoot(event_i^1, …, event_i^t)
    Σ_i^t   = Sign_{sk_i}(root_i^t)

The agent periodically commits `(root_i^t, Σ_i^t)` to an external
audit node (see `committer.AuditCommitter`).  Inclusion proofs let any
third party verify that a particular event is part of the committed
batch without revealing the rest of the batch.

We use SHA-256 with the *Certificate Transparency* RFC 6962 leaf/internal
domain separation (`0x00` for leaves, `0x01` for internals) to defeat
second-preimage attacks across the leaf/internal boundary.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..crypto.primitives import H


_LEAF_PREFIX = b"\x00"
_NODE_PREFIX = b"\x01"


def _hash_leaf(data: bytes) -> bytes:
    return H(_LEAF_PREFIX, data)


def _hash_node(left: bytes, right: bytes) -> bytes:
    return H(_NODE_PREFIX, left, right)


@dataclass(frozen=True)
class InclusionProof:
    """RFC 6962-style inclusion proof for a single leaf."""

    leaf_index: int
    leaf_count: int
    siblings: list[bytes]


def merkle_root(leaves: list[bytes]) -> bytes:
    """Return the RFC 6962 Merkle tree hash of `leaves`.

    Convention for an empty list: H('') (matches RFC 6962).
    """

    if not leaves:
        return H()
    nodes = [_hash_leaf(b) for b in leaves]
    while len(nodes) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                nxt.append(_hash_node(nodes[i], nodes[i + 1]))
            else:
                # Odd-leaf carry (RFC 6962): the last node is promoted as-is.
                nxt.append(nodes[i])
        nodes = nxt
    return nodes[0]


def build_proof(leaves: list[bytes], index: int) -> InclusionProof:
    if not 0 <= index < len(leaves):
        raise IndexError("leaf index out of range")

    siblings: list[bytes] = []
    nodes = [_hash_leaf(b) for b in leaves]
    cur = index
    while len(nodes) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(nodes), 2):
            if i + 1 < len(nodes):
                left, right = nodes[i], nodes[i + 1]
                if i == cur or i + 1 == cur:
                    siblings.append(right if i == cur else left)
                nxt.append(_hash_node(left, right))
            else:
                nxt.append(nodes[i])
        cur //= 2
        nodes = nxt
    return InclusionProof(leaf_index=index, leaf_count=len(leaves), siblings=siblings)


def verify_proof(leaf: bytes, proof: InclusionProof, root: bytes) -> bool:
    """Verify an RFC 6962 inclusion proof."""

    if not 0 <= proof.leaf_index < proof.leaf_count:
        return False

    cur = _hash_leaf(leaf)
    idx = proof.leaf_index
    last = proof.leaf_count - 1
    sibling_iter = iter(proof.siblings)

    while last > 0:
        if idx % 2 == 0 and idx == last:
            # Odd-carry: this node is promoted; no sibling consumed.
            pass
        else:
            sib = next(sibling_iter, None)
            if sib is None:
                return False
            if idx % 2 == 0:
                cur = _hash_node(cur, sib)
            else:
                cur = _hash_node(sib, cur)
        idx //= 2
        last //= 2

    if next(sibling_iter, None) is not None:
        return False
    return cur == root
