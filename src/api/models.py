"""
Pydantic models for API request/response validation.
Comprehensive data models for cybersecurity intelligence API.
"""

from typing import List, Dict, Any, Optional, Union
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, Field, validator


class QueryMode(str, Enum):
    """Query execution modes."""
    AUTO = "auto"
    FAST = "fast" 
    COMPREHENSIVE = "comprehensive"
    DETAILED = "detailed"


class AnalysisDepth(str, Enum):
    """Analysis depth levels."""
    TACTICAL = "tactical"
    OPERATIONAL = "operational"
    STRATEGIC = "strategic"


class CoordinationStrategyEnum(str, Enum):
    """Coordination strategies for multi-agent execution."""
    SINGLE_AGENT = "single_agent"
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"
    HIERARCHICAL = "hierarchical"


class QueryRequest(BaseModel):
    """Request model for intelligence queries."""
    
    query: str = Field(
        ..., 
        min_length=1, 
        max_length=1000,
        description="Intelligence query string",
        example="What are the latest critical vulnerabilities in Microsoft Windows?"
    )
    
    mode: QueryMode = Field(
        default=QueryMode.AUTO,
        description="Query execution mode (auto, fast, comprehensive, detailed)"
    )
    
    limit: int = Field(
        default=20,
        ge=1,
        le=100,
        description="Maximum number of results to return"
    )
    
    context: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Additional context for query processing"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "query": "Analyze APT29 recent campaigns and TTPs",
                "mode": "comprehensive",
                "limit": 25,
                "context": {
                    "time_range": "last_30_days",
                    "sectors": ["government", "healthcare"]
                }
            }
        }


class IntelligenceRequest(QueryRequest):
    """Extended request model for advanced intelligence queries."""
    
    coordination_strategy: CoordinationStrategyEnum = Field(
        default=CoordinationStrategyEnum.HIERARCHICAL,
        description="Multi-agent coordination strategy"
    )
    
    analysis_depth: AnalysisDepth = Field(
        default=AnalysisDepth.OPERATIONAL,
        description="Depth of analysis (tactical, operational, strategic)"
    )
    
    focus_areas: List[str] = Field(
        default=[],
        description="Specific areas of focus for analysis",
        example=["attribution", "ttps", "infrastructure"]
    )
    
    confidence_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Minimum confidence threshold for results"
    )
    
    include_raw_data: bool = Field(
        default=False,
        description="Include raw database records in response"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "query": "Comprehensive analysis of Lazarus Group activities",
                "mode": "detailed",
                "limit": 50,
                "coordination_strategy": "parallel",
                "analysis_depth": "strategic",
                "focus_areas": ["attribution", "infrastructure", "malware"],
                "confidence_threshold": 0.7,
                "include_raw_data": True
            }
        }


class IntelligenceResult(BaseModel):
    """Individual intelligence result item."""
    
    type: str = Field(
        description="Type of intelligence result",
        example="threat_report"
    )
    
    title: Optional[str] = Field(
        description="Title or identifier of the result"
    )
    
    content: Optional[str] = Field(
        description="Main content or description"
    )
    
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Confidence score for this result"
    )
    
    source: Optional[str] = Field(
        description="Data source of the result"
    )
    
    timestamp: Optional[datetime] = Field(
        description="Timestamp of the intelligence"
    )
    
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional metadata for the result"
    )
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class QueryResponse(BaseModel):
    """Response model for intelligence queries."""
    
    query: str = Field(
        description="Original query string"
    )
    
    results: List[Union[IntelligenceResult, Dict[str, Any]]] = Field(
        description="List of intelligence results"
    )
    
    total_results: Optional[int] = Field(
        default=0,
        description="Total number of results found"
    )
    
    confidence: Optional[float] = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Overall confidence score for the results"
    )
    
    response_time: Optional[float] = Field(
        default=0.0,
        description="Query processing time in seconds"
    )
    
    source: Optional[List[str]] = Field(
        default_factory=list,
        description="Data sources used for the query"
    )
    
    metadata: Dict[str, Any] = Field(
        description="Query execution metadata"
    )
    
    success: bool = Field(
        description="Whether the query was processed successfully"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "query": "Latest APT29 campaigns",
                "results": [
                    {
                        "type": "threat_report",
                        "title": "APT29 targeting healthcare organizations",
                        "confidence": 0.85,
                        "source": "threat_intelligence",
                        "timestamp": "2024-01-15T10:30:00Z"
                    }
                ],
                "total_results": 15,
                "confidence": 0.82,
                "response_time": 0.45,
                "source": ["postgresql", "qdrant"],
                "metadata": {
                    "strategy": "hierarchical",
                    "agents_used": ["threat_intelligence", "vulnerability"]
                },
                "success": True
            }
        }


class HealthStatus(str, Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ComponentHealth(BaseModel):
    """Health status for individual components."""
    
    name: str = Field(description="Component name")
    status: HealthStatus = Field(description="Health status")
    response_time: Optional[float] = Field(description="Response time in seconds")
    last_check: datetime = Field(description="Last health check timestamp")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional health details")
    error: Optional[str] = Field(description="Error message if unhealthy")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }


class HealthResponse(BaseModel):
    """Comprehensive health check response."""
    
    status: HealthStatus = Field(description="Overall system health")
    timestamp: datetime = Field(description="Health check timestamp") 
    version: str = Field(description="Application version")
    uptime: float = Field(description="Uptime in seconds")
    
    components: List[ComponentHealth] = Field(
        description="Individual component health status"
    )
    
    statistics: Dict[str, Any] = Field(
        default_factory=dict,
        description="System statistics and metrics"
    )
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat()
        }
        schema_extra = {
            "example": {
                "status": "healthy",
                "timestamp": "2024-01-15T10:30:00Z",
                "version": "1.0.0",
                "uptime": 86400.5,
                "components": [
                    {
                        "name": "postgresql",
                        "status": "healthy", 
                        "response_time": 0.05,
                        "last_check": "2024-01-15T10:30:00Z",
                        "details": {"connections": 15}
                    }
                ],
                "statistics": {
                    "total_queries": 1250,
                    "avg_response_time": 0.45
                }
            }
        }


class AgentStatus(BaseModel):
    """Status information for individual agents."""
    
    name: str = Field(description="Agent name")
    description: str = Field(description="Agent description")
    initialized: bool = Field(description="Whether agent is initialized")
    execution_stats: Dict[str, Any] = Field(description="Agent execution statistics")
    last_execution: Optional[datetime] = Field(description="Last execution timestamp")
    
    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class SystemStatus(BaseModel):
    """Comprehensive system status information."""
    
    agents: List[AgentStatus] = Field(description="Agent status information")
    routing_stats: Dict[str, Any] = Field(description="Query routing statistics")
    database_stats: Dict[str, Any] = Field(description="Database statistics")
    performance_metrics: Dict[str, Any] = Field(description="Performance metrics")
    
    class Config:
        schema_extra = {
            "example": {
                "agents": [
                    {
                        "name": "ThreatIntelligenceAgent",
                        "description": "Expert in threat actor analysis",
                        "initialized": True,
                        "execution_stats": {
                            "total_executions": 150,
                            "success_rate": 0.95
                        }
                    }
                ],
                "routing_stats": {
                    "total_queries": 1000,
                    "success_rate": 0.98
                },
                "database_stats": {
                    "postgresql_connections": 15,
                    "qdrant_collections": 3
                },
                "performance_metrics": {
                    "avg_response_time": 0.45,
                    "p95_response_time": 1.2
                }
            }
        }


class ErrorResponse(BaseModel):
    """Error response model."""
    
    error: Dict[str, Any] = Field(
        description="Error information"
    )
    
    class Config:
        schema_extra = {
            "example": {
                "error": {
                    "message": "Query processing failed",
                    "status_code": 500,
                    "timestamp": "2024-01-15T10:30:00Z",
                    "path": "/api/v1/query"
                }
            }
        }


class CVESearchRequest(BaseModel):
    """Request model for CVE-specific searches."""
    
    cve_id: Optional[str] = Field(
        description="Specific CVE identifier",
        pattern=r"CVE-\d{4}-\d{4,}",
        example="CVE-2024-0001"
    )
    
    severity: Optional[str] = Field(
        description="CVSS severity level",
        pattern=r"^(critical|high|medium|low)$"
    )
    
    vendor: Optional[str] = Field(
        description="Vendor name filter"
    )
    
    product: Optional[str] = Field(
        description="Product name filter"
    )
    
    date_from: Optional[datetime] = Field(
        description="Start date for published vulnerabilities"
    )
    
    date_to: Optional[datetime] = Field(
        description="End date for published vulnerabilities" 
    )
    
    limit: int = Field(
        default=50,
        ge=1,
        le=500,
        description="Maximum number of results"
    )
    
    @validator('date_to')
    def validate_date_range(cls, v, values):
        if v and 'date_from' in values and values['date_from']:
            if v < values['date_from']:
                raise ValueError('date_to must be after date_from')
        return v


class ThreatActorSearchRequest(BaseModel):
    """Request model for threat actor searches."""
    
    actor_name: Optional[str] = Field(
        description="Threat actor name or alias"
    )
    
    actor_type: Optional[str] = Field(
        description="Type of threat actor",
        pattern=r"^(apt|nation_state|cybercriminal|hacktivist|insider)$"
    )
    
    active_only: bool = Field(
        default=True,
        description="Only return active threat actors"
    )
    
    sectors: List[str] = Field(
        default=[],
        description="Targeted sectors filter"
    )
    
    countries: List[str] = Field(
        default=[],
        description="Origin or target countries filter"
    )
    
    limit: int = Field(
        default=25,
        ge=1,
        le=100,
        description="Maximum number of results"
    )