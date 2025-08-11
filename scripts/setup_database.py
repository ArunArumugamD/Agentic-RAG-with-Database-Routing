"""
Database setup and initialization script.
Creates tables, indexes, and loads sample data.
"""

import sys
import asyncio
from pathlib import Path
from datetime import datetime

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database import db_manager
from src.utils.logging_config import setup_logging, get_logger


async def setup_database():
    """Setup database with tables and sample data."""
    
    logger = get_logger(__name__)
    
    try:
        print("[INFO] Initializing database...")
        
        # Initialize database connection
        await db_manager.initialize()
        
        # Create tables
        from src.database.schemas import Base
        async with db_manager._postgres_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        print("[SUCCESS] Database initialization completed successfully!")
        
        # Display database statistics
        health_info = await db_manager.health_check()
        if health_info.get("postgres", {}).get("status") == "healthy":
            print("[INFO] Database connection is healthy")
        else:
            print(f"[WARNING] Database health check failed: {health_info}")
        
    except Exception as e:
        logger.error(f"Database setup failed: {str(e)}")
        print(f"[ERROR] Database setup failed: {e}")
        sys.exit(1)
    
    finally:
        await db_manager.close()


async def load_sample_data():
    """Load sample cybersecurity data for testing."""
    
    logger = get_logger(__name__)
    
    try:
        # Initialize database connection
        await db_manager.initialize()
        
        # Sample CVE data
        sample_cves = [
            {
                "cve_id": "CVE-2024-0001", 
                "description": "Critical remote code execution vulnerability in web application framework",
                "cvss_score": 9.8,
                "severity": "CRITICAL",
                "published_date": datetime(2024, 1, 15),
                "vendor": "ExampleCorp",
                "product": "WebFramework",
                "version_affected": "2.1.0"
            },
            {
                "cve_id": "CVE-2024-0002",
                "description": "SQL injection vulnerability in database connector", 
                "cvss_score": 8.1,
                "severity": "HIGH",
                "published_date": datetime(2024, 2, 20),
                "vendor": "DataSoft",
                "product": "DBConnector", 
                "version_affected": "1.5.2"
            }
        ]
        
        # Sample threat actor data
        sample_actors = [
            {
                "name": "APT29",
                "aliases": "Cozy Bear, The Dukes",
                "description": "Advanced persistent threat group attributed to Russian intelligence",
                "first_seen": datetime(2008, 1, 1),
                "country_origin": "Russia",
                "motivation": "Espionage"
            },
            {
                "name": "Lazarus Group", 
                "aliases": "Hidden Cobra, APT38",
                "description": "North Korean state-sponsored cybercriminal group",
                "first_seen": datetime(2009, 1, 1),
                "country_origin": "North Korea",
                "motivation": "Financial gain, Espionage"
            }
        ]
        
        # Add sample data
        async with db_manager.get_postgres_session() as session:
            from src.database.schemas import CVERecord, ThreatActor
            
            # Add sample CVEs
            for cve_data in sample_cves:
                cve = CVERecord(**cve_data)
                session.add(cve)
            
            # Add sample threat actors  
            for actor_data in sample_actors:
                actor = ThreatActor(**actor_data)
                session.add(actor)
            
            await session.commit()
            print(f"[SUCCESS] Loaded {len(sample_cves)} CVEs and {len(sample_actors)} threat actors")
            
    except Exception as e:
        logger.error(f"Sample data loading failed: {str(e)}")
        print(f"[WARNING] Sample data loading failed: {e}")

    finally:
        await db_manager.close()


def main():
    """Main entry point."""
    
    setup_logging()
    
    print("""
    =============================================================================
                           Database Setup Script                                
                      Agentic RAG Database Initialization                       
    =============================================================================
    """)
    
    # Run database setup
    asyncio.run(setup_database())
    
    # Optionally load sample data
    response = input("\n[PROMPT] Would you like to load sample data for testing? (y/N): ")
    if response.lower() in ['y', 'yes']:
        asyncio.run(load_sample_data())
    
    print("\n[SUCCESS] Database setup completed successfully!")
    print("   You can now start the server with: python scripts/run_server.py")


if __name__ == "__main__":
    main()