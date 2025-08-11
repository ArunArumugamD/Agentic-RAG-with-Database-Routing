"""
Intelligence endpoints for cybersecurity threat intelligence queries.
Specialized endpoints for different types of intelligence analysis.
"""

import logging
from typing import List, Dict, Any
from datetime import datetime

from fastapi import APIRouter, HTTPException, Depends, Request, BackgroundTasks
from fastapi.responses import StreamingResponse

from ..models import (
    QueryRequest, QueryResponse, CVESearchRequest, ThreatActorSearchRequest,
    IntelligenceResult, AnalysisDepth
)
from ...agents import CoordinationStrategy

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/cve", response_model=QueryResponse)
async def search_cve(
    request: CVESearchRequest,
    background_tasks: BackgroundTasks,
    req: Request
) -> QueryResponse:
    """
    Search for CVE vulnerabilities with specific filters.
    
    Optimized endpoint for CVE database queries with:
    - CVE ID lookup
    - Severity-based filtering
    - Vendor/product filtering
    - Date range queries
    """
    start_time = datetime.utcnow()
    
    try:
        # Build query string from request parameters
        query_parts = []
        
        if request.cve_id:
            query_parts.append(f"CVE {request.cve_id}")
        
        if request.severity:
            query_parts.append(f"severity:{request.severity}")
        
        if request.vendor:
            query_parts.append(f"vendor:{request.vendor}")
        
        if request.product:
            query_parts.append(f"product:{request.product}")
        
        if request.date_from:
            query_parts.append(f"after:{request.date_from.strftime('%Y-%m-%d')}")
        
        if request.date_to:
            query_parts.append(f"before:{request.date_to.strftime('%Y-%m-%d')}")
        
        if not query_parts:
            query_parts.append("recent vulnerabilities")
        
        query = " ".join(query_parts)
        
        # Use vulnerability agent with structured focus
        route_engine = req.app.state.route_engine
        agent_coordinator = req.app.state.agent_coordinator
        
        result = await agent_coordinator.coordinate_analysis(
            query=query,
            context={
                "search_type": "cve_search",
                "structured_query": True,
                "cve_filters": {
                    "cve_id": request.cve_id,
                    "severity": request.severity,
                    "vendor": request.vendor,
                    "product": request.product,
                    "date_from": request.date_from,
                    "date_to": request.date_to
                }
            },
            strategy=CoordinationStrategy.SINGLE_AGENT
        )
        
        response_time = (datetime.utcnow() - start_time).total_seconds()
        
        return QueryResponse(
            query=query,
            results=result["results"][:request.limit],
            total_results=len(result["results"]),
            confidence=result["confidence"],
            response_time=response_time,
            source=result.get("coordination", {}).get("agents_used", ["vulnerability"]),
            metadata={
                "search_type": "cve_search",
                "filters_applied": {
                    "cve_id": request.cve_id,
                    "severity": request.severity,
                    "vendor": request.vendor,
                    "product": request.product
                },
                "timestamp": start_time.isoformat()
            },
            success=result["success"]
        )
        
    except Exception as e:
        logger.error(f"CVE search failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/threat-actors", response_model=QueryResponse)
async def search_threat_actors(
    request: ThreatActorSearchRequest,
    background_tasks: BackgroundTasks,
    req: Request
) -> QueryResponse:
    """
    Search for threat actor intelligence.
    
    Specialized endpoint for threat actor queries with:
    - Actor name and alias search
    - Activity-based filtering
    - Geographic and sector targeting
    - Campaign association analysis
    """
    start_time = datetime.utcnow()
    
    try:
        # Build query string for threat actors
        query_parts = []
        
        if request.actor_name:
            query_parts.append(f"threat actor {request.actor_name}")
        
        if request.actor_type:
            query_parts.append(f"type:{request.actor_type}")
        
        if request.active_only:
            query_parts.append("active")
        
        if request.sectors:
            query_parts.append(f"sectors:{','.join(request.sectors)}")
        
        if request.countries:
            query_parts.append(f"countries:{','.join(request.countries)}")
        
        if not query_parts:
            query_parts.append("threat actors recent activity")
        
        query = " ".join(query_parts)
        
        # Use threat intelligence agent
        agent_coordinator = req.app.state.agent_coordinator
        
        result = await agent_coordinator.coordinate_analysis(
            query=query,
            context={
                "search_type": "threat_actor_search",
                "intelligence_focus": "actor",
                "actor_filters": {
                    "name": request.actor_name,
                    "type": request.actor_type,
                    "active_only": request.active_only,
                    "sectors": request.sectors,
                    "countries": request.countries
                }
            },
            strategy=CoordinationStrategy.HIERARCHICAL
        )
        
        response_time = (datetime.utcnow() - start_time).total_seconds()
        
        return QueryResponse(
            query=query,
            results=result["results"][:request.limit],
            total_results=len(result["results"]),
            confidence=result["confidence"],
            response_time=response_time,
            source=result.get("coordination", {}).get("agents_used", ["threat_intelligence"]),
            metadata={
                "search_type": "threat_actor_search",
                "filters_applied": {
                    "actor_name": request.actor_name,
                    "actor_type": request.actor_type,
                    "active_only": request.active_only,
                    "sectors": request.sectors,
                    "countries": request.countries
                },
                "timestamp": start_time.isoformat()
            },
            success=result["success"]
        )
        
    except Exception as e:
        logger.error(f"Threat actor search failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics/vulnerabilities", response_model=QueryResponse)
async def vulnerability_statistics(
    req: Request,
    days: int = 30,
    severity: str = None,
    vendor: str = None
) -> QueryResponse:
    """
    Get vulnerability statistics and trends.
    
    Provides statistical analysis of vulnerability data including:
    - Severity distribution
    - Temporal trends
    - Vendor/product breakdowns
    - Exploit availability statistics
    """
    start_time = datetime.utcnow()
    
    try:
        # Build statistics query
        query_parts = ["vulnerability statistics"]
        
        if days:
            query_parts.append(f"last {days} days")
        
        if severity:
            query_parts.append(f"severity {severity}")
        
        if vendor:
            query_parts.append(f"vendor {vendor}")
        
        query = " ".join(query_parts)
        
        route_engine = req.app.state.route_engine
        
        # Use routing engine directly for statistical queries
        result = await route_engine.route_query(
            query=query,
            user_context={
                "query_type": "statistics",
                "time_range": days,
                "severity_filter": severity,
                "vendor_filter": vendor
            }
        )
        
        response_time = (datetime.utcnow() - start_time).total_seconds()
        
        return QueryResponse(
            query=query,
            results=result.data,
            total_results=len(result.data),
            confidence=result.confidence_score,
            response_time=response_time,
            source=[result.source],
            metadata={
                "query_type": "statistics",
                "parameters": {
                    "days": days,
                    "severity": severity,
                    "vendor": vendor
                },
                "timestamp": start_time.isoformat()
            },
            success=result.status.value == "success"
        )
        
    except Exception as e:
        logger.error(f"Vulnerability statistics failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/statistics/threat-landscape", response_model=QueryResponse)
async def threat_landscape_statistics(
    req: Request,
    days: int = 90,
    actor_type: str = None,
    sectors: List[str] = None
) -> QueryResponse:
    """
    Get threat landscape statistics and analysis.
    
    Provides comprehensive threat landscape overview:
    - Active threat actor statistics
    - Campaign activity trends
    - Sector targeting analysis
    - Geographic threat distribution
    """
    start_time = datetime.utcnow()
    
    try:
        query_parts = ["threat landscape statistics"]
        
        if days:
            query_parts.append(f"last {days} days")
        
        if actor_type:
            query_parts.append(f"actor type {actor_type}")
        
        if sectors:
            query_parts.append(f"sectors {','.join(sectors)}")
        
        query = " ".join(query_parts)
        
        agent_coordinator = req.app.state.agent_coordinator
        
        result = await agent_coordinator.coordinate_analysis(
            query=query,
            context={
                "search_type": "landscape_statistics",
                "intelligence_focus": "landscape",
                "time_range": days,
                "actor_type": actor_type,
                "sectors": sectors or []
            },
            strategy=CoordinationStrategy.SINGLE_AGENT
        )
        
        response_time = (datetime.utcnow() - start_time).total_seconds()
        
        return QueryResponse(
            query=query,
            results=result["results"],
            total_results=len(result["results"]),
            confidence=result["confidence"],
            response_time=response_time,
            source=result.get("coordination", {}).get("agents_used", ["threat_intelligence"]),
            metadata={
                "query_type": "landscape_statistics",
                "parameters": {
                    "days": days,
                    "actor_type": actor_type,
                    "sectors": sectors
                },
                "timestamp": start_time.isoformat()
            },
            success=result["success"]
        )
        
    except Exception as e:
        logger.error(f"Threat landscape statistics failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/campaign", response_model=QueryResponse)
async def analyze_campaign(
    campaign_name: str,
    analysis_depth: AnalysisDepth = AnalysisDepth.OPERATIONAL,
    req: Request = None
) -> QueryResponse:
    """
    Comprehensive campaign analysis.
    
    Provides deep analysis of threat campaigns including:
    - Attribution assessment
    - TTP analysis
    - Infrastructure mapping
    - Timeline reconstruction
    - Victim impact assessment
    """
    start_time = datetime.utcnow()
    
    try:
        query = f"analyze campaign {campaign_name}"
        
        agent_coordinator = req.app.state.agent_coordinator
        
        result = await agent_coordinator.coordinate_analysis(
            query=query,
            context={
                "search_type": "campaign_analysis",
                "intelligence_focus": "campaign",
                "analysis_depth": analysis_depth.value,
                "campaign_name": campaign_name
            },
            strategy=CoordinationStrategy.SEQUENTIAL
        )
        
        response_time = (datetime.utcnow() - start_time).total_seconds()
        
        return QueryResponse(
            query=query,
            results=result["results"],
            total_results=len(result["results"]),
            confidence=result["confidence"],
            response_time=response_time,
            source=result.get("coordination", {}).get("agents_used", ["threat_intelligence"]),
            metadata={
                "analysis_type": "campaign_analysis",
                "campaign_name": campaign_name,
                "analysis_depth": analysis_depth.value,
                "timestamp": start_time.isoformat()
            },
            success=result["success"]
        )
        
    except Exception as e:
        logger.error(f"Campaign analysis failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/trending", response_model=QueryResponse)
async def trending_intelligence(
    req: Request,
    hours: int = 24,
    limit: int = 20
) -> QueryResponse:
    """
    Get trending cybersecurity intelligence.
    
    Provides real-time trending intelligence including:
    - Recently disclosed vulnerabilities
    - Emerging threat campaigns
    - Active exploitation attempts
    - IOC feeds and updates
    """
    start_time = datetime.utcnow()
    
    try:
        query = f"trending cybersecurity intelligence last {hours} hours"
        
        agent_coordinator = req.app.state.agent_coordinator
        
        result = await agent_coordinator.coordinate_analysis(
            query=query,
            context={
                "search_type": "trending_intelligence",
                "time_range": hours,
                "real_time": True
            },
            strategy=CoordinationStrategy.PARALLEL
        )
        
        response_time = (datetime.utcnow() - start_time).total_seconds()
        
        return QueryResponse(
            query=query,
            results=result["results"][:limit],
            total_results=len(result["results"]),
            confidence=result["confidence"],
            response_time=response_time,
            source=result.get("coordination", {}).get("agents_used", ["threat_intelligence", "vulnerability"]),
            metadata={
                "query_type": "trending",
                "time_range_hours": hours,
                "timestamp": start_time.isoformat()
            },
            success=result["success"]
        )
        
    except Exception as e:
        logger.error(f"Trending intelligence failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))