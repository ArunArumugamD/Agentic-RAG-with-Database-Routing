"""
Database setup and initialization script.
Creates tables, indexes, and loads sample data.
"""

import sys
import asyncio
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database import initialize_database, db_manager
from src.utils.logging_config import setup_logging, get_logger


async def setup_database():
    """Setup database with tables and sample data."""
    
    logger = get_logger(__name__)
    
    try:
        print("🔧 Initializing database...")
        await initialize_database()
        
        print("✅ Database initialization completed successfully!")
        
        # Display database statistics
        health_info = await db_manager.health_check()
        if health_info["status"] == "healthy":
            stats = health_info.get("statistics", {})
            print(f"""
📊 Database Statistics:
   • CVE Entries: {stats.get('cve_entries', 0):,}
   • Threat Reports: {stats.get('threat_reports', 0):,}  
   • Threat Actors: {stats.get('threat_actors', 0):,}
   
🔗 Connection Details:
   • Pool Size: {health_info.get('pool_status', {}).get('pool_size', 'N/A')}
   • Active Connections: {health_info.get('pool_status', {}).get('checked_out', 'N/A')}
            """)
        else:
            print(f"⚠️ Database health check failed: {health_info}")
        
    except Exception as e:
        logger.error(f"Database setup failed: {str(e)}")
        print(f"❌ Database setup failed: {e}")
        sys.exit(1)
    
    finally:
        await db_manager.close()


async def load_sample_data():
    """Load sample cybersecurity data for testing."""
    
    print("📊 Loading sample data...")
    
    # Sample CVE data
    sample_cves = [
        {
            "cve_id": "CVE-2024-0001",
            "description": "Critical remote code execution vulnerability in popular web framework",
            "cvss_v3_score": 9.8,
            "severity": "critical",
            "published_date": "2024-01-15"
        },
        {
            "cve_id": "CVE-2024-0002", 
            "description": "SQL injection vulnerability in enterprise database management system",
            "cvss_v3_score": 8.1,
            "severity": "high",
            "published_date": "2024-01-10"
        }
    ]
    
    # Sample threat actors
    sample_actors = [
        {
            "name": "APT29",
            "aliases": ["Cozy Bear", "The Dukes"],
            "description": "Russian state-sponsored cyber espionage group",
            "actor_type": "nation_state",
            "origin_country": "Russia",
            "is_active": True
        },
        {
            "name": "Lazarus Group",
            "aliases": ["Hidden Cobra", "Guardians of Peace"],
            "description": "North Korean state-sponsored hacking group",
            "actor_type": "nation_state", 
            "origin_country": "North Korea",
            "is_active": True
        }
    ]
    
    try:
        async with db_manager.get_session() as session:
            from src.database.schemas import CVEEntry, ThreatActor
            
            # Add sample CVEs
            for cve_data in sample_cves:
                cve = CVEEntry(**cve_data)
                session.add(cve)
            
            # Add sample threat actors  
            for actor_data in sample_actors:
                actor = ThreatActor(**actor_data)
                session.add(actor)
            
            await session.commit()
            print(f"✅ Loaded {len(sample_cves)} CVEs and {len(sample_actors)} threat actors")
            
    except Exception as e:
        print(f"⚠️ Sample data loading failed: {e}")


def main():
    """Main entry point."""
    
    setup_logging()
    
    print("""
    ╔══════════════════════════════════════════════════════════════════════════════╗
    ║                         Database Setup Script                                ║
    ║                    Agentic RAG Database Initialization                       ║
    ╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    # Run database setup
    asyncio.run(setup_database())
    
    # Optionally load sample data
    response = input("\n📊 Would you like to load sample data for testing? (y/N): ")
    if response.lower() in ['y', 'yes']:
        asyncio.run(load_sample_data())
    
    print("\n🎉 Database setup completed successfully!")
    print("   You can now start the server with: python scripts/run_server.py")


if __name__ == "__main__":
    main()