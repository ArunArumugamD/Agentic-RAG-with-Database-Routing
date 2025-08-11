"""
Database package for Agentic RAG system.
Provides PostgreSQL schema definitions and connection management.
"""

from .connection import (
    db_manager,
    get_postgres_session,
    get_redis_client
)
from .schemas import (
    Base,
    CVERecord,
    MitreAttackTechnique,
    ThreatActor,
    MalwareFamily,
    ThreatCampaign,
    VulnerabilityExploit,
    IOC,
    QueryLog
)
from .postgresql_adapter import PostgreSQLAdapter

__all__ = [
    "db_manager",
    "get_postgres_session",
    "get_redis_client",
    "Base",
    "CVERecord",
    "MitreAttackTechnique",
    "ThreatActor",
    "MalwareFamily",
    "ThreatCampaign",
    "VulnerabilityExploit",
    "IOC",
    "QueryLog",
    "PostgreSQLAdapter"
]