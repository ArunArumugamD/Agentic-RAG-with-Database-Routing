import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, Depends, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
import logging

from config.settings import settings
from src.database.connection import db_manager
from src.routing.route_engine import route_engine
from src.api.models import (
    QueryRequest, QueryResponse, HealthResponse, 
    ErrorResponse, HealthStatus, ComponentHealth
)

logger = logging.getLogger(__name__)

# Track application start time
APP_START_TIME = time.time()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager"""
    # Startup
    logger.info("Starting Agentic RAG application...")
    
    try:
        # Initialize database connections
        await db_manager.initialize()
        logger.info("Database connections initialized")
        
        # Initialize Qdrant collection
        from src.vector_store.qdrant_adapter import qdrant_adapter
        await qdrant_adapter.initialize_collection()
        logger.info("Qdrant collection initialized")
        
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        raise
    
    yield
    
    # Shutdown
    logger.info("Shutting down application...")
    await db_manager.close()
    logger.info("Application shutdown complete")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Intelligent Query Routing System for Cybersecurity Threat Intelligence",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "message": "Internal server error",
                "type": type(exc).__name__,
                "detail": str(exc) if settings.DEBUG else None
            }
        }
    )


@app.get("/", tags=["Root"])
async def root():
    """Serve the main UI"""
    from fastapi.responses import FileResponse
    return FileResponse('static/index.html')


@app.get("/health", response_model=HealthResponse, tags=["Health"])
async def health_check():
    """Comprehensive health check endpoint"""
    from datetime import datetime
    
    components = []
    overall_status = HealthStatus.HEALTHY
    
    # Check database health
    db_health = await db_manager.health_check()
    
    # PostgreSQL health
    pg_status = HealthStatus.HEALTHY if db_health["postgres"]["status"] == "healthy" else HealthStatus.CRITICAL
    components.append(ComponentHealth(
        name="postgresql",
        status=pg_status,
        response_time=db_health["postgres"].get("latency_ms", 0) / 1000,
        last_check=datetime.utcnow(),
        details={"latency_ms": db_health["postgres"].get("latency_ms")},
        error=db_health["postgres"].get("error")
    ))
    
    # Redis health
    redis_status = HealthStatus.HEALTHY if db_health["redis"]["status"] == "healthy" else HealthStatus.DEGRADED
    components.append(ComponentHealth(
        name="redis",
        status=redis_status,
        response_time=db_health["redis"].get("latency_ms", 0) / 1000,
        last_check=datetime.utcnow(),
        details={"latency_ms": db_health["redis"].get("latency_ms")},
        error=db_health["redis"].get("error")
    ))
    
    # Qdrant health
    from src.vector_store.qdrant_adapter import qdrant_adapter
    qdrant_health = await qdrant_adapter.health_check()
    qdrant_status = HealthStatus.HEALTHY if qdrant_health.get("status") == "healthy" else HealthStatus.DEGRADED
    components.append(ComponentHealth(
        name="qdrant",
        status=qdrant_status,
        response_time=0,
        last_check=datetime.utcnow(),
        details={"document_count": qdrant_health.get("document_count", 0)},
        error=qdrant_health.get("error")
    ))
    
    # Determine overall status
    if any(c.status == HealthStatus.CRITICAL for c in components):
        overall_status = HealthStatus.CRITICAL
    elif any(c.status == HealthStatus.DEGRADED for c in components):
        overall_status = HealthStatus.DEGRADED
    
    return HealthResponse(
        status=overall_status,
        timestamp=datetime.utcnow(),
        version=settings.APP_VERSION,
        uptime=time.time() - APP_START_TIME,
        components=components,
        statistics={
            "total_queries": 0,  # TODO: Implement query counting
            "avg_response_time": 0
        }
    )


@app.post(
    "/api/v1/query",
    response_model=QueryResponse,
    tags=["Query"]
)
async def execute_query(request: QueryRequest):
    """
    Execute an intelligent threat intelligence query.
    
    The system will automatically:
    - Classify the query type
    - Route to appropriate database(s)
    - Apply self-correction if needed
    - Return relevant results with confidence scoring
    """
    try:
        start_time = time.time()
        
        # Execute query through routing engine
        result = await route_engine.route_and_execute(
            query=request.query,
            mode=request.mode
        )
        
        # Return result directly with all fields the frontend expects
        response_data = {
            "query": request.query,
            "results": result.get("results", []),
            "summary": result.get("summary"),
            "metadata": result.get("metadata", {}),
            "relevance_metrics": result.get("relevance_metrics", {}),
            "success": True
        }
        
        return response_data
        
    except Exception as e:
        logger.error(f"Query execution failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Query execution failed: {str(e)}"
        )


@app.post(
    "/api/v1/query/advanced",
    tags=["Query"]
)
async def execute_advanced_query(request: QueryRequest):
    """
    Execute an advanced query with custom routing preferences.
    
    This endpoint provides more control over:
    - Routing preferences
    - Confidence thresholds
    - Self-correction behavior
    - Caching strategies
    """
    try:
        start_time = time.time()
        
        # Build custom routing plan
        routing_overrides = {}
        if hasattr(request, 'routing_preference'):
            routing_overrides['data_source'] = request.routing_preference
        if hasattr(request, 'confidence_threshold'):
            routing_overrides['confidence_threshold'] = request.confidence_threshold
        
        # Execute with custom parameters
        result = await route_engine.route_and_execute(
            query=request.query,
            mode=request.mode if hasattr(request, 'mode') else "balanced"
        )
        
        # Apply confidence threshold filtering if specified
        if hasattr(request, 'confidence_threshold'):
            filtered_results = [
                r for r in result.get("results", [])
                if r.get("confidence", 0) >= request.confidence_threshold
            ]
            result["results"] = filtered_results
            result["metadata"]["filtered_count"] = len(filtered_results)
        
        response_data = {
            "query": request.query,
            "results": result.get("results", []),
            "summary": result.get("summary"),
            "metadata": result.get("metadata", {}),
            "relevance_metrics": result.get("relevance_metrics", {}),
            "success": True
        }
        
        return response_data
        
    except Exception as e:
        logger.error(f"Advanced query execution failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=500,
            detail=f"Query execution failed: {str(e)}"
        )


@app.get(
    "/api/v1/statistics",
    tags=["Statistics"]
)
async def get_statistics():
    """
    Get system statistics and performance metrics.
    
    Returns:
    - Query execution statistics
    - Database performance metrics
    - Cache hit rates
    - Self-correction statistics
    """
    try:
        from src.database.postgresql_adapter import PostgreSQLAdapter
        
        async with db_manager.get_postgres_session() as session:
            adapter = PostgreSQLAdapter(session)
            
            # Get query statistics from database
            # This would need implementation in the adapter
            stats = {
                "uptime_seconds": time.time() - APP_START_TIME,
                "databases": {
                    "postgresql": {"status": "connected"},
                    "qdrant": {"status": "connected"},
                    "redis": {"status": "connected"}
                },
                "performance": {
                    "average_response_time_ms": 0,
                    "total_queries": 0,
                    "cache_hit_rate": 0,
                    "self_correction_rate": 0
                }
            }
            
            return stats
            
    except Exception as e:
        logger.error(f"Failed to get statistics: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve statistics"
        )


@app.get(
    "/api/v1/threat-landscape",
    tags=["Intelligence"]
)
async def get_threat_landscape(days: int = 30):
    """
    Get threat landscape summary for the specified time period.
    
    Args:
        days: Number of days to look back (default: 30)
    
    Returns:
        Summary of threat landscape including:
        - Critical CVE count
        - Active threat actors
        - Recent campaigns
        - Top targeted sectors
    """
    try:
        from src.database.postgresql_adapter import PostgreSQLAdapter
        
        async with db_manager.get_postgres_session() as session:
            adapter = PostgreSQLAdapter(session)
            summary = await adapter.get_threat_landscape_summary(days)
            
            return summary
            
    except Exception as e:
        logger.error(f"Failed to get threat landscape: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to retrieve threat landscape"
        )


@app.get("/api/v1/status", tags=["Admin"])
async def get_status():
    """Get detailed system status"""
    return {
        "status": "operational",
        "version": settings.APP_VERSION,
        "environment": "development" if settings.DEBUG else "production",
        "uptime_seconds": time.time() - APP_START_TIME,
        "configuration": {
            "llm_provider": settings.LLM_PROVIDER,
            "llm_model": settings.LLM_MODEL,
            "databases": ["postgresql", "qdrant", "redis"]
        }
    }


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "src.api.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        log_level=settings.LOG_LEVEL.lower()
    )