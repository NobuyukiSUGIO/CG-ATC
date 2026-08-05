"""CG-ATC tamper-evident audit log (paper §III-F)."""

from .committer import AuditCommitter, Commitment, CommitterSink, InMemoryCommitterSink
from .hashchain import AuditRecord, HashChainLog
from .merkle import InclusionProof, build_proof, merkle_root, verify_proof

__all__ = [
    "AuditCommitter",
    "AuditRecord",
    "Commitment",
    "CommitterSink",
    "HashChainLog",
    "InMemoryCommitterSink",
    "InclusionProof",
    "build_proof",
    "merkle_root",
    "verify_proof",
]
