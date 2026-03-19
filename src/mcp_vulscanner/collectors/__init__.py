"""Collector interfaces for research data ingestion."""

from .advisory_corpus import DatasetSyncSummary, load_advisory_descriptors, sync_advisory_corpus

__all__ = ["DatasetSyncSummary", "load_advisory_descriptors", "sync_advisory_corpus"]
