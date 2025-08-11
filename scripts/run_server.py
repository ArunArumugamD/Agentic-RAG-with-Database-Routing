#!/usr/bin/env python
"""
Server startup script for the Agentic RAG application.
"""

import sys
import logging
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def check_requirements():
    """Check if all required services are available"""
    import socket
    
    services = [
        ("PostgreSQL", "localhost", 5432),
        ("Qdrant", "localhost", 6333),
        ("Redis", "localhost", 6379)
    ]
    
    all_available = True
    for service, host, port in services:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((host, port))
        sock.close()
        
        if result == 0:
            logger.info(f"✓ {service} is available on {host}:{port}")
        else:
            logger.warning(f"✗ {service} is not available on {host}:{port}")
            logger.warning(f"  Please start {service} or run: docker-compose up -d")
            all_available = False
    
    return all_available


def main():
    """Main server startup function"""
    try:
        from config.settings import settings
        import uvicorn
        
        logger.info("=" * 60)
        logger.info(f"Starting {settings.APP_NAME}")
        logger.info(f"Version: {settings.APP_VERSION}")
        logger.info("=" * 60)
        
        # Check if databases are running
        if not check_requirements():
            logger.error("\nSome required services are not available!")
            logger.info("\nTo start all services with Docker:")
            logger.info("  docker-compose up -d")
            logger.info("\nOr install and start them manually.")
            return
        
        logger.info("\nConfiguration:")
        logger.info(f"  LLM Provider: {settings.LLM_PROVIDER}")
        logger.info(f"  LLM Model: {settings.LLM_MODEL}")
        logger.info(f"  API Host: {settings.API_HOST}")
        logger.info(f"  API Port: {settings.API_PORT}")
        
        logger.info("\nStarting server...")
        logger.info(f"API Documentation: http://{settings.API_HOST}:{settings.API_PORT}/docs")
        logger.info(f"Health Check: http://{settings.API_HOST}:{settings.API_PORT}/health")
        
        # Ensure logs directory exists
        logs_dir = project_root / "logs"
        logs_dir.mkdir(exist_ok=True)
        
        # Run the server
        uvicorn.run(
            "src.api.main:app",
            host=settings.API_HOST,
            port=settings.API_PORT,
            reload=settings.DEBUG,
            log_level=settings.LOG_LEVEL.lower()
        )
        
    except ImportError as e:
        logger.error(f"Import error: {e}")
        logger.error("\nPlease ensure all dependencies are installed:")
        logger.error("  pip install -r requirements.txt")
        sys.exit(1)
        
    except Exception as e:
        logger.error(f"Failed to start server: {e}", exc_info=True)
        sys.exit(1)


if __name__ == "__main__":
    main()