from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore"
    )
    
    # Application
    APP_NAME: str = "Agentic RAG with Database Routing"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"
    
    # API Configuration
    API_HOST: str = "0.0.0.0"
    API_PORT: int = 8000
    API_PREFIX: str = "/api/v1"
    
    # Database Configuration
    POSTGRES_HOST: str = "localhost"
    POSTGRES_PORT: int = 5432
    POSTGRES_DB: str = "threat_intelligence"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = "password"
    DATABASE_URL: str = Field(
        default="postgresql://postgres:password@localhost:5432/threat_intelligence"
    )
    
    # Qdrant Configuration
    QDRANT_HOST: str = "localhost"
    QDRANT_PORT: int = 6333
    QDRANT_COLLECTION_NAME: str = "threat_documents"
    
    # Redis Configuration
    REDIS_HOST: str = "localhost"
    REDIS_PORT: int = 6379
    REDIS_DB: int = 0
    REDIS_PASSWORD: str = ""
    
    # AI/LLM Configuration (Free Open Source)
    LLM_PROVIDER: str = "groq"
    LLM_MODEL: str = "deepseek-r1-distill-llama-70b"
    GROQ_API_KEY: str = Field(default="")
    EMBEDDING_MODEL: str = "sentence-transformers/all-MiniLM-L6-v2"
    MAX_TOKENS: int = 2000
    TEMPERATURE: float = 0.1
    
    # Alternative provider settings
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    HF_MODEL: str = "microsoft/DialoGPT-medium"
    HF_API_TOKEN: str = Field(default="")
    
    # Security
    SECRET_KEY: str = Field(default="change-this-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    
    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 100
    
    # Monitoring
    ENABLE_METRICS: bool = True
    METRICS_PORT: int = 8001
    
    # Data Sources
    MITRE_ATTACK_URL: str = (
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
    )
    CVE_API_URL: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    MAX_CVE_REQUESTS_PER_MINUTE: int = 5
    
    # Performance
    DB_POOL_SIZE: int = 10
    DB_MAX_OVERFLOW: int = 20
    QUERY_TIMEOUT: int = 30
    CACHE_TTL: int = 3600
    
    @property
    def redis_url(self) -> str:
        if self.REDIS_PASSWORD:
            return f"redis://:{self.REDIS_PASSWORD}@{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"
        return f"redis://{self.REDIS_HOST}:{self.REDIS_PORT}/{self.REDIS_DB}"


# Global settings instance
settings = Settings()