"""
Health check endpoints for system monitoring and observability.
Comprehensive health checks for all system components.
"""

import logging
import psutil
from typing import Dict, Any
from datetime import datetime, timedelta

from fastapi import APIRouter, Request, HTTPException

from ..models import HealthResponse, ComponentHealth, HealthStatus
from config.settings import settings

logger = logging.getLogger(__name__)

router = APIRouter()

# Track application start time for uptime calculation
_start_time = datetime.utcnow()


@router.get("/", response_model=HealthResponse)
async def health_check(req: Request) -> HealthResponse:
    """
    Comprehensive system health check.
    
    Checks all critical system components:
    - Database connections (PostgreSQL, Qdrant)
    - Agent status and initialization
    - System resources (memory, CPU, disk)
    - External service dependencies
    """
    check_time = datetime.utcnow()
    
    try:
        components = []
        overall_status = HealthStatus.HEALTHY
        
        # Database health checks
        db_health = await _check_database_health(req)
        components.extend(db_health["components"])
        if db_health["status"] != HealthStatus.HEALTHY:
            overall_status = HealthStatus.DEGRADED
        
        # Agent health checks
        agent_health = await _check_agents_health(req)
        components.extend(agent_health["components"])
        if agent_health["status"] != HealthStatus.HEALTHY and overall_status == HealthStatus.HEALTHY:
            overall_status = HealthStatus.DEGRADED
        
        # System resource checks
        system_health = _check_system_resources()
        components.append(system_health)
        if system_health.status != HealthStatus.HEALTHY:
            if system_health.status == HealthStatus.CRITICAL:
                overall_status = HealthStatus.CRITICAL
            elif overall_status == HealthStatus.HEALTHY:
                overall_status = HealthStatus.DEGRADED
        
        # Calculate uptime
        uptime = (check_time - _start_time).total_seconds()
        
        # Get system statistics
        statistics = await _get_system_statistics(req)
        
        return HealthResponse(
            status=overall_status,
            timestamp=check_time,
            version=settings.api_version,
            uptime=uptime,
            components=components,
            statistics=statistics
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return HealthResponse(
            status=HealthStatus.CRITICAL,
            timestamp=check_time,
            version=settings.api_version,
            uptime=(check_time - _start_time).total_seconds(),
            components=[
                ComponentHealth(
                    name="health_check",
                    status=HealthStatus.CRITICAL,
                    response_time=None,
                    last_check=check_time,
                    error=str(e)
                )
            ],
            statistics={}
        )


@router.get("/live")
async def liveness_probe():
    """
    Kubernetes liveness probe endpoint.
    Simple check to verify the application is running.
    """
    return {"status": "alive", "timestamp": datetime.utcnow().isoformat()}


@router.get("/ready")
async def readiness_probe(req: Request):
    """
    Kubernetes readiness probe endpoint.
    Checks if the application is ready to serve requests.
    """
    try:
        # Check critical dependencies
        db_manager = req.app.state.db_manager
        
        # Quick database connectivity check
        db_health = await db_manager.health_check()
        if db_health["status"] != "healthy":
            raise HTTPException(status_code=503, detail="Database not ready")
        
        # Check agent coordinator initialization
        agent_coordinator = req.app.state.agent_coordinator
        if not hasattr(agent_coordinator, 'agents') or not agent_coordinator.agents:
            raise HTTPException(status_code=503, detail="Agents not initialized")
        
        return {
            "status": "ready", 
            "timestamp": datetime.utcnow().isoformat(),
            "database": "connected",
            "agents": len(agent_coordinator.agents)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Readiness check failed: {str(e)}")
        raise HTTPException(status_code=503, detail=str(e))


@router.get("/database")
async def database_health(req: Request) -> Dict[str, Any]:
    """
    Detailed database health information.
    """
    try:
        db_manager = req.app.state.db_manager
        health_info = await db_manager.health_check()
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "postgresql": health_info,
            "qdrant": {
                "status": "not_implemented",
                "message": "Qdrant integration pending"
            }
        }
        
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/agents")
async def agents_health(req: Request) -> Dict[str, Any]:
    """
    Detailed agent status information.
    """
    try:
        agent_coordinator = req.app.state.agent_coordinator
        agent_status = agent_coordinator.get_agent_status()
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            **agent_status
        }
        
    except Exception as e:
        logger.error(f"Agent health check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/metrics")
async def system_metrics(req: Request) -> Dict[str, Any]:
    """
    Detailed system metrics for monitoring.
    """
    try:
        # System resource metrics
        cpu_percent = psutil.cpu_percent(interval=1)
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        
        # Application metrics
        statistics = await _get_system_statistics(req)
        
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "system": {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": memory.available / (1024**3),
                "disk_percent": disk.percent,
                "disk_free_gb": disk.free / (1024**3)
            },
            "application": statistics,
            "uptime_seconds": (datetime.utcnow() - _start_time).total_seconds()
        }
        
    except Exception as e:
        logger.error(f"Metrics collection failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


async def _check_database_health(req: Request) -> Dict[str, Any]:
    """Check database component health."""
    components = []
    overall_status = HealthStatus.HEALTHY
    
    try:
        db_manager = req.app.state.db_manager
        start_time = datetime.utcnow()
        
        # PostgreSQL health check
        db_health = await db_manager.health_check()
        response_time = (datetime.utcnow() - start_time).total_seconds()
        
        if db_health["status"] == "healthy":
            pg_status = HealthStatus.HEALTHY
        else:
            pg_status = HealthStatus.CRITICAL
            overall_status = HealthStatus.CRITICAL
        
        components.append(ComponentHealth(
            name="postgresql",
            status=pg_status,
            response_time=response_time,
            last_check=datetime.utcnow(),
            details=db_health.get("statistics", {}),
            error=db_health.get("error")
        ))
        
        # Qdrant health check (placeholder)
        components.append(ComponentHealth(
            name="qdrant",
            status=HealthStatus.UNKNOWN,
            response_time=None,
            last_check=datetime.utcnow(),
            details={"status": "not_implemented"},
            error="Qdrant integration pending"
        ))
        
    except Exception as e:
        logger.error(f"Database health check failed: {str(e)}")
        components.append(ComponentHealth(
            name="database_check",
            status=HealthStatus.CRITICAL,
            response_time=None,
            last_check=datetime.utcnow(),
            error=str(e)
        ))
        overall_status = HealthStatus.CRITICAL
    
    return {
        "status": overall_status,
        "components": components
    }


async def _check_agents_health(req: Request) -> Dict[str, Any]:
    """Check agent component health."""
    components = []
    overall_status = HealthStatus.HEALTHY
    
    try:
        agent_coordinator = req.app.state.agent_coordinator
        start_time = datetime.utcnow()
        
        # Agent coordinator health check
        coordinator_health = await agent_coordinator.health_check()
        response_time = (datetime.utcnow() - start_time).total_seconds()
        
        if coordinator_health["overall_status"] == "healthy":
            coordinator_status = HealthStatus.HEALTHY
        elif coordinator_health["overall_status"] == "degraded":
            coordinator_status = HealthStatus.DEGRADED
            overall_status = HealthStatus.DEGRADED
        else:
            coordinator_status = HealthStatus.CRITICAL
            overall_status = HealthStatus.CRITICAL
        
        components.append(ComponentHealth(
            name="agent_coordinator",
            status=coordinator_status,
            response_time=response_time,
            last_check=datetime.utcnow(),
            details={
                "total_agents": len(coordinator_health["agents"]),
                "healthy_agents": sum(1 for a in coordinator_health["agents"].values() if a["healthy"])
            },
            error=None
        ))
        
        # Individual agent health checks
        for agent_name, agent_health in coordinator_health["agents"].items():
            agent_status = HealthStatus.HEALTHY if agent_health["healthy"] else HealthStatus.CRITICAL
            
            components.append(ComponentHealth(
                name=f"agent_{agent_name}",
                status=agent_status,
                response_time=None,
                last_check=datetime.utcnow(),
                details={
                    "initialized": agent_health["initialized"]
                },
                error=agent_health.get("error")
            ))
        
    except Exception as e:
        logger.error(f"Agent health check failed: {str(e)}")
        components.append(ComponentHealth(
            name="agents_check",
            status=HealthStatus.CRITICAL,
            response_time=None,
            last_check=datetime.utcnow(),
            error=str(e)
        ))
        overall_status = HealthStatus.CRITICAL
    
    return {
        "status": overall_status,
        "components": components
    }


def _check_system_resources() -> ComponentHealth:
    """Check system resource health."""
    try:
        # CPU check
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Memory check
        memory = psutil.virtual_memory()
        
        # Disk check
        disk = psutil.disk_usage('/')
        
        # Determine overall status
        if cpu_percent > 90 or memory.percent > 90 or disk.percent > 90:
            status = HealthStatus.CRITICAL
        elif cpu_percent > 80 or memory.percent > 80 or disk.percent > 80:
            status = HealthStatus.DEGRADED
        else:
            status = HealthStatus.HEALTHY
        
        return ComponentHealth(
            name="system_resources",
            status=status,
            response_time=None,
            last_check=datetime.utcnow(),
            details={
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": round(memory.available / (1024**3), 2),
                "disk_percent": disk.percent,
                "disk_free_gb": round(disk.free / (1024**3), 2)
            },
            error=None
        )
        
    except Exception as e:
        return ComponentHealth(
            name="system_resources",
            status=HealthStatus.CRITICAL,
            response_time=None,
            last_check=datetime.utcnow(),
            details={},
            error=str(e)
        )


async def _get_system_statistics(req: Request) -> Dict[str, Any]:
    """Get comprehensive system statistics."""
    try:
        statistics = {
            "application": {
                "version": settings.api_version,
                "environment": settings.environment.value,
                "uptime_seconds": (datetime.utcnow() - _start_time).total_seconds()
            }
        }
        
        # Add routing engine statistics if available
        if hasattr(req.app.state, 'route_engine'):
            route_stats = req.app.state.route_engine.get_routing_stats()
            statistics["routing"] = route_stats
        
        # Add agent coordination statistics if available
        if hasattr(req.app.state, 'agent_coordinator'):
            agent_status = req.app.state.agent_coordinator.get_agent_status()
            statistics["agents"] = agent_status["coordination_stats"]
        
        return statistics
        
    except Exception as e:
        logger.error(f"Failed to collect statistics: {str(e)}")
        return {"error": str(e)}