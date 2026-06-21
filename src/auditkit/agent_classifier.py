"""Backward-compatible entry point for AI classification.

The actual implementation now lives in auditkit.agents. This module re-exports
the public symbols used by external callers.
"""

from auditkit.agents.contexts.credential import CredentialAgent
from auditkit.agents.runner import classify_batch, merge_reports

BATCH_SIZE = CredentialAgent.batch_size

__all__ = ["BATCH_SIZE", "classify_batch", "merge_reports"]
