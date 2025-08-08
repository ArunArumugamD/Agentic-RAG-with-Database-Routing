"""
Monitoring and metrics collection utilities for the Agentic RAG system.
Provides comprehensive observability with Prometheus-compatible metrics.
"""

import time
import psutil
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
import threading
from contextlib import contextmanager

from prometheus_client import Counter, Histogram, Gauge, Info, generate_latest
from prometheus_client.core import CollectorRegistry

from config.settings import settings
from .logging_config import get_logger

logger = get_logger(__name__)


@dataclass
class MetricPoint:
    """Individual metric data point."""
    timestamp: datetime
    value: float
    labels: Dict[str, str] = field(default_factory=dict)


class MetricsCollector:
    """
    Comprehensive metrics collection for the Agentic RAG system.
    Collects performance, business, and system metrics.
    """
    
    def __init__(self):
        self.registry = CollectorRegistry()
        self._initialize_metrics()
        self._time_series_data = defaultdict(lambda: deque(maxlen=1000))
        self._lock = threading.Lock()
        
    def _initialize_metrics(self):
        """Initialize Prometheus metrics."""
        
        # API Metrics
        self.api_requests_total = Counter(
            'api_requests_total',
            'Total API requests',
            ['method', 'endpoint', 'status_code'],
            registry=self.registry
        )
        
        self.api_request_duration = Histogram(
            'api_request_duration_seconds',
            'API request duration',
            ['method', 'endpoint'],
            registry=self.registry,
            buckets=[0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        
        # Query Processing Metrics
        self.query_processing_total = Counter(
            'query_processing_total',
            'Total queries processed',
            ['query_type', 'agent', 'success'],
            registry=self.registry
        )
        
        self.query_processing_duration = Histogram(
            'query_processing_duration_seconds',
            'Query processing duration',
            ['query_type', 'agent'],
            registry=self.registry,
            buckets=[0.1, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0]
        )
        
        self.query_confidence = Histogram(
            'query_confidence_score',
            'Query result confidence scores',
            ['query_type', 'agent'],
            registry=self.registry,
            buckets=[0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]
        )
        
        # Database Metrics
        self.database_operations_total = Counter(
            'database_operations_total',
            'Total database operations',
            ['database', 'operation', 'success'],
            registry=self.registry
        )
        
        self.database_operation_duration = Histogram(
            'database_operation_duration_seconds',
            'Database operation duration',
            ['database', 'operation'],
            registry=self.registry,
            buckets=[0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0]
        )
        
        self.database_connection_pool = Gauge(
            'database_connection_pool_size',
            'Database connection pool size',
            ['database', 'status'],
            registry=self.registry
        )
        
        # Agent Metrics
        self.agent_executions_total = Counter(
            'agent_executions_total',
            'Total agent executions',
            ['agent', 'success'],
            registry=self.registry
        )
        
        self.agent_execution_duration = Histogram(
            'agent_execution_duration_seconds',
            'Agent execution duration',
            ['agent'],
            registry=self.registry,
            buckets=[0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0]
        )
        
        # System Metrics
        self.system_cpu_usage = Gauge(
            'system_cpu_usage_percent',
            'System CPU usage percentage',
            registry=self.registry
        )
        
        self.system_memory_usage = Gauge(
            'system_memory_usage_bytes',
            'System memory usage in bytes',
            registry=self.registry
        )
        
        self.system_disk_usage = Gauge(
            'system_disk_usage_percent',
            'System disk usage percentage',
            registry=self.registry
        )
        
        # Business Metrics
        self.threat_intelligence_queries = Counter(
            'threat_intelligence_queries_total',
            'Total threat intelligence queries',
            ['intelligence_type', 'severity'],
            registry=self.registry
        )
        
        self.vulnerabilities_processed = Counter(
            'vulnerabilities_processed_total',
            'Total vulnerabilities processed',
            ['severity', 'vendor'],
            registry=self.registry
        )
        
        # Application Info
        self.app_info = Info(
            'application_info',
            'Application information',
            registry=self.registry
        )
        
        self.app_info.info({
            'version': settings.api_version,
            'environment': settings.environment.value,
            'debug_mode': str(settings.debug)
        })
    
    def record_api_request(self, method: str, endpoint: str, status_code: int, duration: float):
        """Record API request metrics."""
        self.api_requests_total.labels(
            method=method,
            endpoint=endpoint, 
            status_code=status_code
        ).inc()
        
        self.api_request_duration.labels(
            method=method,
            endpoint=endpoint
        ).observe(duration)
        
        # Store time series data
        with self._lock:
            self._time_series_data['api_requests'].append(
                MetricPoint(
                    timestamp=datetime.utcnow(),
                    value=1,
                    labels={
                        'method': method,
                        'endpoint': endpoint,
                        'status_code': str(status_code)
                    }
                )
            )
    
    def record_query_processing(
        self, 
        query_type: str, 
        agent: str, 
        duration: float, 
        confidence: float, 
        success: bool
    ):
        """Record query processing metrics."""
        self.query_processing_total.labels(
            query_type=query_type,
            agent=agent,
            success=str(success).lower()
        ).inc()
        
        self.query_processing_duration.labels(
            query_type=query_type,
            agent=agent
        ).observe(duration)
        
        self.query_confidence.labels(
            query_type=query_type,
            agent=agent
        ).observe(confidence)
        
        # Store time series data
        with self._lock:
            self._time_series_data['query_processing'].append(
                MetricPoint(
                    timestamp=datetime.utcnow(),
                    value=duration,
                    labels={
                        'query_type': query_type,
                        'agent': agent,
                        'confidence': str(confidence),
                        'success': str(success)
                    }
                )
            )
    
    def record_database_operation(
        self, 
        database: str, 
        operation: str, 
        duration: float, 
        success: bool
    ):
        """Record database operation metrics."""
        self.database_operations_total.labels(
            database=database,
            operation=operation,
            success=str(success).lower()
        ).inc()
        
        self.database_operation_duration.labels(
            database=database,
            operation=operation
        ).observe(duration)
    
    def update_database_pool_metrics(self, database: str, pool_stats: Dict[str, int]):
        """Update database connection pool metrics."""
        for status, count in pool_stats.items():
            self.database_connection_pool.labels(
                database=database,
                status=status
            ).set(count)
    
    def record_agent_execution(self, agent: str, duration: float, success: bool):
        """Record agent execution metrics."""
        self.agent_executions_total.labels(
            agent=agent,
            success=str(success).lower()
        ).inc()
        
        self.agent_execution_duration.labels(agent=agent).observe(duration)
    
    def update_system_metrics(self):
        """Update system resource metrics."""
        try:
            # CPU usage
            cpu_percent = psutil.cpu_percent(interval=1)
            self.system_cpu_usage.set(cpu_percent)
            
            # Memory usage
            memory = psutil.virtual_memory()
            self.system_memory_usage.set(memory.used)
            
            # Disk usage
            disk = psutil.disk_usage('/')
            self.system_disk_usage.set(disk.percent)
            
        except Exception as e:
            logger.error(f"Failed to update system metrics: {str(e)}")
    
    def record_threat_intelligence_query(self, intelligence_type: str, severity: str = "unknown"):
        """Record threat intelligence business metrics."""
        self.threat_intelligence_queries.labels(
            intelligence_type=intelligence_type,
            severity=severity
        ).inc()
    
    def record_vulnerability_processed(self, severity: str, vendor: str = "unknown"):
        """Record vulnerability processing business metrics."""
        self.vulnerabilities_processed.labels(
            severity=severity,
            vendor=vendor
        ).inc()
    
    def get_prometheus_metrics(self) -> str:
        """Get metrics in Prometheus format."""
        return generate_latest(self.registry).decode('utf-8')
    
    def get_time_series_data(self, metric_name: str, hours: int = 24) -> List[MetricPoint]:
        """Get time series data for a specific metric."""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        with self._lock:
            return [
                point for point in self._time_series_data[metric_name]
                if point.timestamp > cutoff_time
            ]
    
    def get_summary_stats(self) -> Dict[str, Any]:
        """Get summary statistics for monitoring dashboard."""
        now = datetime.utcnow()
        one_hour_ago = now - timedelta(hours=1)
        
        # Calculate request rate (requests per minute)
        recent_requests = [
            point for point in self._time_series_data['api_requests']
            if point.timestamp > one_hour_ago
        ]
        
        request_rate = len(recent_requests) / 60 if recent_requests else 0
        
        # Calculate average processing time
        recent_processing = [
            point for point in self._time_series_data['query_processing']
            if point.timestamp > one_hour_ago
        ]
        
        avg_processing_time = (
            sum(point.value for point in recent_processing) / len(recent_processing)
            if recent_processing else 0
        )
        
        # System resources
        try:
            cpu_percent = psutil.cpu_percent()
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
        except:
            cpu_percent = memory = disk = None
        
        return {
            "timestamp": now.isoformat(),
            "performance": {
                "requests_per_minute": round(request_rate, 2),
                "average_processing_time": round(avg_processing_time, 3),
                "total_requests_1h": len(recent_requests),
                "total_queries_1h": len(recent_processing)
            },
            "system": {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent if memory else None,
                "disk_percent": disk.percent if disk else None
            },
            "application": {
                "version": settings.api_version,
                "environment": settings.environment.value,
                "uptime_hours": self.get_uptime_hours()
            }
        }
    
    def get_uptime_hours(self) -> float:
        """Get application uptime in hours."""
        # This would track from application start time
        # For now, return a placeholder
        return 24.0


# Global metrics collector instance
metrics_collector = MetricsCollector()


@contextmanager
def monitor_operation(operation_name: str, labels: Dict[str, str] = None):
    """
    Context manager for monitoring operations with timing.
    
    Usage:
        with monitor_operation("database_query", {"table": "cve_entries"}):
            # Your operation here
            result = execute_query()
    """
    start_time = time.time()
    labels = labels or {}
    
    try:
        yield
        duration = time.time() - start_time
        success = True
        
        # Record success metrics
        logger.info(
            f"Operation {operation_name} completed successfully",
            extra={
                "operation": operation_name,
                "duration": duration,
                "success": success,
                **labels
            }
        )
        
    except Exception as e:
        duration = time.time() - start_time
        success = False
        
        # Record failure metrics
        logger.error(
            f"Operation {operation_name} failed: {str(e)}",
            extra={
                "operation": operation_name,
                "duration": duration,
                "success": success,
                "error": str(e),
                **labels
            }
        )
        
        raise


class PerformanceTracker:
    """Track performance metrics for specific operations."""
    
    def __init__(self, name: str):
        self.name = name
        self.measurements = deque(maxlen=100)
        self._lock = threading.Lock()
    
    def record(self, duration: float, success: bool = True, **kwargs):
        """Record a performance measurement."""
        with self._lock:
            self.measurements.append({
                "timestamp": datetime.utcnow(),
                "duration": duration,
                "success": success,
                **kwargs
            })
    
    @contextmanager
    def measure(self, **kwargs):
        """Context manager for automatic measurement."""
        start_time = time.time()
        success = True
        
        try:
            yield
        except Exception as e:
            success = False
            raise
        finally:
            duration = time.time() - start_time
            self.record(duration, success, **kwargs)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics."""
        with self._lock:
            if not self.measurements:
                return {"count": 0, "avg_duration": 0, "success_rate": 0}
            
            durations = [m["duration"] for m in self.measurements]
            successes = [m["success"] for m in self.measurements]
            
            return {
                "count": len(self.measurements),
                "avg_duration": sum(durations) / len(durations),
                "min_duration": min(durations),
                "max_duration": max(durations),
                "success_rate": sum(successes) / len(successes),
                "last_measurement": self.measurements[-1]["timestamp"].isoformat()
            }


# Global performance trackers
query_tracker = PerformanceTracker("query_processing")
database_tracker = PerformanceTracker("database_operations")
agent_tracker = PerformanceTracker("agent_execution")


def get_health_metrics() -> Dict[str, Any]:
    """Get comprehensive health and performance metrics."""
    return {
        "timestamp": datetime.utcnow().isoformat(),
        "system": {
            "cpu_percent": psutil.cpu_percent(),
            "memory": dict(psutil.virtual_memory()._asdict()),
            "disk": dict(psutil.disk_usage('/')._asdict())
        },
        "performance": {
            "query_processing": query_tracker.get_stats(),
            "database_operations": database_tracker.get_stats(),
            "agent_execution": agent_tracker.get_stats()
        },
        "summary": metrics_collector.get_summary_stats()
    }