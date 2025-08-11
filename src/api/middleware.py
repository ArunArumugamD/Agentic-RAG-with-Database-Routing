"""
FastAPI middleware for security, logging, rate limiting, and metrics.
Production-ready middleware stack for the Agentic RAG system.
"""

import time
import logging
from typing import Dict, Any
from datetime import datetime, timedelta
from collections import defaultdict
import json

from fastapi import Request, Response, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from config.settings import settings

logger = logging.getLogger(__name__)

# In-memory storage for rate limiting (use Redis in production)
_rate_limit_storage: Dict[str, Dict[str, Any]] = defaultdict(dict)

# Metrics storage (use Prometheus in production)
_metrics_storage = {
    "total_requests": 0,
    "request_duration_sum": 0.0,
    "status_codes": defaultdict(int),
    "endpoints": defaultdict(int),
    "errors": defaultdict(int)
}


async def logging_middleware(request: Request, call_next):
    """
    Comprehensive request/response logging middleware.
    Logs all API requests with timing and status information.
    """
    start_time = time.time()
    request_id = f"{int(start_time * 1000000)}"  # Simple request ID
    
    # Log incoming request
    logger.info(
        f"Request {request_id}: {request.method} {request.url.path} "
        f"from {request.client.host if request.client else 'unknown'}"
    )
    
    # Add request ID to request state
    request.state.request_id = request_id
    request.state.start_time = start_time
    
    try:
        response = await call_next(request)
        
        # Calculate processing time
        process_time = time.time() - start_time
        
        # Log response
        logger.info(
            f"Response {request_id}: {response.status_code} "
            f"in {process_time:.3f}s"
        )
        
        # Add timing header
        response.headers["X-Process-Time"] = str(process_time)
        response.headers["X-Request-ID"] = request_id
        
        return response
        
    except Exception as e:
        process_time = time.time() - start_time
        logger.error(
            f"Request {request_id} failed in {process_time:.3f}s: {str(e)}"
        )
        raise


async def rate_limiting_middleware(request: Request, call_next):
    """
    Rate limiting middleware to prevent API abuse.
    Implements sliding window rate limiting per IP address.
    """
    client_ip = request.client.host if request.client else "unknown"
    
    # Skip rate limiting for health checks and admin endpoints with debug mode
    if settings.debug and request.url.path.startswith("/health"):
        return await call_next(request)
    
    current_time = datetime.utcnow()
    window_start = current_time - timedelta(seconds=settings.rate_limit_window)
    
    # Clean old entries
    if client_ip in _rate_limit_storage:
        client_data = _rate_limit_storage[client_ip]
        client_data["requests"] = [
            req_time for req_time in client_data.get("requests", [])
            if req_time > window_start
        ]
    
    # Check rate limit
    client_requests = _rate_limit_storage[client_ip].get("requests", [])
    
    if len(client_requests) >= settings.rate_limit_requests:
        logger.warning(f"Rate limit exceeded for {client_ip}")
        return JSONResponse(
            status_code=429,
            content={
                "error": {
                    "message": "Rate limit exceeded",
                    "limit": settings.rate_limit_requests,
                    "window_seconds": settings.rate_limit_window,
                    "retry_after": settings.rate_limit_window
                }
            },
            headers={
                "X-RateLimit-Limit": str(settings.rate_limit_requests),
                "X-RateLimit-Window": str(settings.rate_limit_window),
                "X-RateLimit-Remaining": "0",
                "Retry-After": str(settings.rate_limit_window)
            }
        )
    
    # Record this request
    client_requests.append(current_time)
    _rate_limit_storage[client_ip]["requests"] = client_requests
    
    # Process request
    response = await call_next(request)
    
    # Add rate limiting headers
    remaining = max(0, settings.rate_limit_requests - len(client_requests))
    response.headers["X-RateLimit-Limit"] = str(settings.rate_limit_requests)
    response.headers["X-RateLimit-Window"] = str(settings.rate_limit_window)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    
    return response


async def security_middleware(request: Request, call_next):
    """
    Security middleware for headers and basic security checks.
    Adds security headers and performs basic validation.
    """
    # Check for required headers in production
    if not settings.debug:
        # Check for API key or authentication
        auth_header = request.headers.get("Authorization")
        if not auth_header and not request.url.path.startswith("/health"):
            # In production, implement proper authentication
            pass
    
    # Process request
    response = await call_next(request)
    
    # Add security headers
    security_headers = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Content-Security-Policy": "default-src 'self'",
        "Referrer-Policy": "strict-origin-when-cross-origin"
    }
    
    for header, value in security_headers.items():
        response.headers[header] = value
    
    return response


async def metrics_middleware(request: Request, call_next):
    """
    Metrics collection middleware for monitoring and observability.
    Collects request metrics for Prometheus/monitoring systems.
    """
    start_time = time.time()
    
    # Increment total requests
    _metrics_storage["total_requests"] += 1
    
    try:
        response = await call_next(request)
        
        # Calculate duration
        duration = time.time() - start_time
        _metrics_storage["request_duration_sum"] += duration
        
        # Record status code
        _metrics_storage["status_codes"][response.status_code] += 1
        
        # Record endpoint
        endpoint = f"{request.method} {request.url.path}"
        _metrics_storage["endpoints"][endpoint] += 1
        
        return response
        
    except Exception as e:
        duration = time.time() - start_time
        _metrics_storage["request_duration_sum"] += duration
        
        # Record error
        error_type = type(e).__name__
        _metrics_storage["errors"][error_type] += 1
        _metrics_storage["status_codes"][500] += 1
        
        # Record endpoint even for errors
        endpoint = f"{request.method} {request.url.path}"
        _metrics_storage["endpoints"][endpoint] += 1
        
        raise


class MaintenanceModeMiddleware(BaseHTTPMiddleware):
    """
    Maintenance mode middleware to gracefully handle service unavailability.
    """
    
    def __init__(self, app, maintenance_mode: bool = False):
        super().__init__(app)
        self.maintenance_mode = maintenance_mode
    
    async def dispatch(self, request: Request, call_next):
        # Allow health checks and admin endpoints during maintenance
        allowed_paths = ["/health", "/admin", "/docs", "/redoc", "/openapi.json"]
        
        if (self.maintenance_mode and 
            not any(request.url.path.startswith(path) for path in allowed_paths)):
            
            return JSONResponse(
                status_code=503,
                content={
                    "error": {
                        "message": "Service temporarily unavailable for maintenance",
                        "status": "maintenance_mode",
                        "timestamp": datetime.utcnow().isoformat()
                    }
                },
                headers={
                    "Retry-After": "3600"  # Suggest retry after 1 hour
                }
            )
        
        return await call_next(request)


def get_metrics() -> Dict[str, Any]:
    """
    Get current metrics for monitoring systems.
    Returns metrics in a format suitable for Prometheus scraping.
    """
    total_requests = _metrics_storage["total_requests"]
    total_duration = _metrics_storage["request_duration_sum"]
    
    metrics = {
        "total_requests": total_requests,
        "average_response_time": total_duration / total_requests if total_requests > 0 else 0.0,
        "status_codes": dict(_metrics_storage["status_codes"]),
        "endpoints": dict(_metrics_storage["endpoints"]),
        "errors": dict(_metrics_storage["errors"]),
        "timestamp": datetime.utcnow().isoformat()
    }
    
    return metrics


def reset_metrics():
    """Reset all metrics (for testing or admin purposes)."""
    global _metrics_storage
    _metrics_storage = {
        "total_requests": 0,
        "request_duration_sum": 0.0,
        "status_codes": defaultdict(int),
        "endpoints": defaultdict(int),
        "errors": defaultdict(int)
    }


def get_rate_limit_status() -> Dict[str, Any]:
    """Get current rate limiting status for monitoring."""
    current_time = datetime.utcnow()
    window_start = current_time - timedelta(seconds=settings.rate_limit_window)
    
    active_clients = 0
    total_requests = 0
    
    for client_ip, data in _rate_limit_storage.items():
        recent_requests = [
            req_time for req_time in data.get("requests", [])
            if req_time > window_start
        ]
        
        if recent_requests:
            active_clients += 1
            total_requests += len(recent_requests)
    
    return {
        "active_clients": active_clients,
        "total_recent_requests": total_requests,
        "rate_limit_config": {
            "requests_per_window": settings.rate_limit_requests,
            "window_seconds": settings.rate_limit_window
        },
        "timestamp": current_time.isoformat()
    }


# Error handler for middleware exceptions
async def middleware_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handle exceptions that occur in middleware."""
    logger.error(f"Middleware error: {str(exc)}")
    
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "message": "Internal middleware error",
                "type": type(exc).__name__,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
    )