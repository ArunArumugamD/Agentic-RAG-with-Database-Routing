import asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool
from sqlalchemy import event, text
from contextlib import asynccontextmanager
from typing import AsyncGenerator
import redis.asyncio as redis
from config.settings import settings
import logging

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages all database connections"""
    
    def __init__(self):
        self._postgres_engine = None
        self._postgres_session = None
        self._redis_client = None
    
    async def initialize(self):
        """Initialize all database connections"""
        await self._init_postgres()
        await self._init_redis()
        logger.info("All database connections initialized successfully")
    
    async def _init_postgres(self):
        """Initialize PostgreSQL connection"""
        try:
            # Create async engine with connection pooling
            self._postgres_engine = create_async_engine(
                settings.DATABASE_URL.replace("postgresql://", "postgresql+asyncpg://"),
                poolclass=NullPool,
                echo=settings.DEBUG
            )
            
            # Create session factory
            self._postgres_session = async_sessionmaker(
                bind=self._postgres_engine,
                class_=AsyncSession,
                expire_on_commit=False
            )
            
            # Test connection
            async with self._postgres_engine.begin() as conn:
                await conn.run_sync(lambda sync_conn: sync_conn.execute(text("SELECT 1")))
                
            logger.info("PostgreSQL connection established")
            
        except Exception as e:
            logger.error(f"Failed to initialize PostgreSQL: {e}")
            raise
    
    async def _init_redis(self):
        """Initialize Redis connection"""
        try:
            redis_url = settings.redis_url
            self._redis_client = redis.from_url(
                redis_url,
                decode_responses=True,
                socket_timeout=5,
                retry_on_timeout=True,
                health_check_interval=30
            )
            
            # Test connection
            await self._redis_client.ping()
            logger.info("Redis connection established")
            
        except Exception as e:
            logger.error(f"Failed to initialize Redis: {e}")
            raise
    
    @asynccontextmanager
    async def get_postgres_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get PostgreSQL session"""
        if not self._postgres_session:
            await self._init_postgres()
        
        async with self._postgres_session() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    
    async def get_redis_client(self) -> redis.Redis:
        """Get Redis client"""
        if not self._redis_client:
            await self._init_redis()
        return self._redis_client
    
    async def close(self):
        """Close all database connections"""
        if self._postgres_engine:
            await self._postgres_engine.dispose()
            
        if self._redis_client:
            await self._redis_client.close()
            
        logger.info("All database connections closed")
    
    async def health_check(self) -> dict:
        """Check health of all database connections"""
        health = {
            "postgres": {"status": "down", "latency_ms": None},
            "redis": {"status": "down", "latency_ms": None}
        }
        
        # Check PostgreSQL
        try:
            import time
            start = time.time()
            async with self.get_postgres_session() as session:
                result = await session.execute(text("SELECT 1"))
                result.fetchone()
            
            health["postgres"]["status"] = "healthy"
            health["postgres"]["latency_ms"] = round((time.time() - start) * 1000, 2)
            
        except Exception as e:
            logger.error(f"PostgreSQL health check failed: {e}")
            health["postgres"]["error"] = str(e)
        
        # Check Redis
        try:
            import time
            start = time.time()
            redis_client = await self.get_redis_client()
            await redis_client.ping()
            
            health["redis"]["status"] = "healthy"
            health["redis"]["latency_ms"] = round((time.time() - start) * 1000, 2)
            
        except Exception as e:
            logger.error(f"Redis health check failed: {e}")
            health["redis"]["error"] = str(e)
        
        return health


# Global database manager instance
db_manager = DatabaseManager()


async def get_postgres_session():
    """Dependency for FastAPI"""
    async with db_manager.get_postgres_session() as session:
        yield session


async def get_redis_client():
    """Dependency for FastAPI"""
    return await db_manager.get_redis_client()


