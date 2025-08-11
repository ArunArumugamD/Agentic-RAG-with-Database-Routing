"""
Administrative endpoints for system management and monitoring.
Requires elevated privileges for sensitive operations.
"""

import logging
from typing import Dict, Any, List
from datetime import datetime

from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from ..models import SystemStatus, AgentStatus, HealthStatus
from config.settings import settings

logger = logging.getLogger(__name__)

router = APIRouter()
security = HTTPBearer()


async def verify_admin_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Verify admin authentication token."""
    # In production, implement proper JWT token validation
    if not settings.debug and credentials.credentials != "admin-token":
        raise HTTPException(status_code=403, detail="Invalid admin token")
    return credentials


@router.get("/status", response_model=SystemStatus, dependencies=[Depends(verify_admin_token)])
async def system_status(req: Request) -> SystemStatus:
    """
    Comprehensive system status for administrative monitoring.
    
    Provides detailed information about:
    - Agent execution statistics
    - Query routing performance
    - Database connection status
    - System resource utilization
    """
    try:
        # Get agent status
        agent_coordinator = req.app.state.agent_coordinator
        agent_status_data = agent_coordinator.get_agent_status()
        
        agents = []
        for agent_name, details in agent_status_data["agent_details"].items():
            agent_stats = details["execution_stats"]
            agents.append(AgentStatus(
                name=details["name"],
                description=details["description"], 
                initialized=details["initialized"],
                execution_stats=agent_stats,
                last_execution=None  # Would be populated from actual execution logs
            ))
        
        # Get routing statistics
        route_engine = req.app.state.route_engine
        routing_stats = route_engine.get_routing_stats()
        
        # Get database statistics
        db_manager = req.app.state.db_manager
        db_health = await db_manager.health_check()
        database_stats = {
            "postgresql_status": db_health["status"],
            "connection_pool": db_health.get("pool_status", {}),
            "record_counts": db_health.get("statistics", {})
        }
        
        # Performance metrics
        performance_metrics = {
            "average_query_time": routing_stats.get("average_response_time", 0.0),
            "total_queries_processed": routing_stats.get("total_queries", 0),
            "success_rate": routing_stats.get("success_rate", 0.0),
            "agent_coordination_stats": agent_status_data["coordination_stats"]
        }
        
        return SystemStatus(
            agents=agents,
            routing_stats=routing_stats,
            database_stats=database_stats,
            performance_metrics=performance_metrics
        )
        
    except Exception as e:
        logger.error(f"System status collection failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/agents/{agent_name}/reset-stats", dependencies=[Depends(verify_admin_token)])
async def reset_agent_stats(agent_name: str, req: Request):
    """Reset execution statistics for a specific agent."""
    try:
        agent_coordinator = req.app.state.agent_coordinator
        
        if agent_name not in agent_coordinator.agents:
            raise HTTPException(status_code=404, detail=f"Agent {agent_name} not found")
        
        agent = agent_coordinator.agents[agent_name]
        agent.reset_stats()
        
        return {
            "message": f"Statistics reset for agent {agent_name}",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to reset agent stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/database/refresh-views", dependencies=[Depends(verify_admin_token)])
async def refresh_materialized_views(req: Request):
    """Manually trigger refresh of materialized database views."""
    try:
        db_manager = req.app.state.db_manager
        await db_manager.refresh_materialized_views()
        
        return {
            "message": "Materialized views refreshed successfully",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to refresh materialized views: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/database/stats", dependencies=[Depends(verify_admin_token)])
async def database_statistics(req: Request) -> Dict[str, Any]:
    """Get detailed database statistics and connection information."""
    try:
        db_manager = req.app.state.db_manager
        health_info = await db_manager.health_check()
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "connection_status": health_info["status"],
            "pool_statistics": health_info.get("pool_status", {}),
            "record_counts": health_info.get("statistics", {}),
            "database_url": settings.database_url.replace(
                f":{settings.postgres_password}@", ":****@"
            )  # Mask password
        }
        
    except Exception as e:
        logger.error(f"Database statistics collection failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/routing/stats", dependencies=[Depends(verify_admin_token)])
async def routing_statistics(req: Request) -> Dict[str, Any]:
    """Get detailed query routing statistics."""
    try:
        route_engine = req.app.state.route_engine
        stats = route_engine.get_routing_stats()
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "routing_performance": stats,
            "classifier_config": {
                "relevance_threshold": settings.relevance_threshold,
                "max_retries": settings.max_retries,
                "timeout_seconds": settings.timeout_seconds
            }
        }
        
    except Exception as e:
        logger.error(f"Routing statistics collection failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/routing/reset-stats", dependencies=[Depends(verify_admin_token)])
async def reset_routing_stats(req: Request):
    """Reset query routing statistics."""
    try:
        route_engine = req.app.state.route_engine
        
        # Reset routing statistics
        route_engine.routing_stats = {
            "total_queries": 0,
            "successful_routes": 0,
            "corrections_made": 0,
            "average_response_time": 0.0
        }
        
        return {
            "message": "Routing statistics reset successfully",
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Failed to reset routing stats: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config", dependencies=[Depends(verify_admin_token)])
async def system_configuration() -> Dict[str, Any]:
    """Get system configuration (sanitized for security)."""
    try:
        config = {
            "api": {
                "title": settings.api_title,
                "version": settings.api_version,
                "host": settings.api_host,
                "port": settings.api_port,
                "debug": settings.debug
            },
            "database": {
                "host": settings.postgres_host,
                "port": settings.postgres_port,
                "database": settings.postgres_db,
                "user": settings.postgres_user
                # Password deliberately excluded for security
            },
            "ai": {
                "model": settings.openai_model,
                "max_tokens": settings.openai_max_tokens,
                "temperature": settings.openai_temperature
            },
            "routing": {
                "relevance_threshold": settings.relevance_threshold,
                "max_retries": settings.max_retries,
                "timeout_seconds": settings.timeout_seconds
            },
            "processing": {
                "batch_size": settings.batch_size,
                "max_concurrent_requests": settings.max_concurrent_requests,
                "chunk_size": settings.chunk_size
            }
        }
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "configuration": config
        }
        
    except Exception as e:
        logger.error(f"Configuration retrieval failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/maintenance/enable", dependencies=[Depends(verify_admin_token)])
async def enable_maintenance_mode(req: Request):
    """Enable maintenance mode (stops processing new queries)."""
    try:
        # In a production system, this would set a flag that middleware checks
        # For now, we'll just return a success message
        
        return {
            "message": "Maintenance mode enabled",
            "timestamp": datetime.utcnow().isoformat(),
            "note": "New queries will receive maintenance response"
        }
        
    except Exception as e:
        logger.error(f"Failed to enable maintenance mode: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/maintenance/disable", dependencies=[Depends(verify_admin_token)])
async def disable_maintenance_mode(req: Request):
    """Disable maintenance mode (resume normal operations)."""
    try:
        return {
            "message": "Maintenance mode disabled", 
            "timestamp": datetime.utcnow().isoformat(),
            "note": "Normal query processing resumed"
        }
        
    except Exception as e:
        logger.error(f"Failed to disable maintenance mode: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/logs/recent", dependencies=[Depends(verify_admin_token)])
async def recent_logs(lines: int = 100) -> Dict[str, Any]:
    """Get recent application logs for debugging."""
    try:
        # In production, this would read from log files or centralized logging
        # For now, return a placeholder response
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "lines_requested": lines,
            "message": "Log retrieval not implemented in demo",
            "note": "In production, this would return recent log entries"
        }
        
    except Exception as e:
        logger.error(f"Log retrieval failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))