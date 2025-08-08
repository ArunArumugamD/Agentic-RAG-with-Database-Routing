"""
Database package for Agentic RAG system.
Provides PostgreSQL schema definitions and connection management.
"""

from .connection import (
    db_manager,
    get_db_session,
    initialize_database,
    periodic_view_refresh
)
from .schemas import (
    Base,
    CVEEntry,
    AffectedProduct,
    ThreatReport,
    ThreatActor,
    ThreatCampaign,
    MalwareFamily,
    ExploitInfo,
    PatchInfo,
    SeverityLevel,
    ThreatActorType
)
from .postgresql_adapter import PostgreSQLAdapter

__all__ = [
    "db_manager",
    "get_db_session", 
    "initialize_database",
    "periodic_view_refresh",
    "Base",
    "CVEEntry",
    "AffectedProduct", 
    "ThreatReport",
    "ThreatActor",
    "ThreatCampaign",
    "MalwareFamily",
    "ExploitInfo",
    "PatchInfo",
    "SeverityLevel",
    "ThreatActorType",
    "PostgreSQLAdapter"
]