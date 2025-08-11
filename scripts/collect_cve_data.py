#!/usr/bin/env python3
"""
CVE Data Collection Script

Collects vulnerability data from the National Vulnerability Database (NVD) API
and populates the PostgreSQL database with structured CVE information.

Features:
- Respects NVD API rate limits (5 requests/minute)
- Handles incremental updates (only new/modified CVEs)
- Robust error handling and retry logic
- Progress tracking and logging
- Validates and normalizes data before storage
"""

import asyncio
import aiohttp
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
import json
import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database.connection import db_manager
from src.database.postgresql_adapter import PostgreSQLAdapter
from src.database.schemas import CVERecord, VulnerabilityExploit
from config.settings import settings

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/cve_collection.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class CVEDataCollector:
    """
    Collects and processes CVE data from the National Vulnerability Database.
    """
    
    def __init__(self):
        self.base_url = settings.CVE_API_URL
        self.rate_limit = settings.MAX_CVE_REQUESTS_PER_MINUTE
        self.request_delay = 60.0 / self.rate_limit  # Seconds between requests
        self.session: Optional[aiohttp.ClientSession] = None
        self.stats = {
            "requests_made": 0,
            "cves_processed": 0,
            "cves_inserted": 0,
            "cves_updated": 0,
            "errors": 0
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={
                'User-Agent': 'ThreatIntelligenceRAG/1.0 (Security Research)',
                'Accept': 'application/json'
            }
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def collect_recent_cves(self, days_back: int = 7) -> None:
        """
        Collect CVEs published or modified in the last N days.
        
        Args:
            days_back: Number of days to look back for CVEs
        """
        logger.info(f"Starting CVE collection for last {days_back} days")
        
        # Calculate date range
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days_back)
        
        start_index = 0
        results_per_page = 100  # NVD allows up to 2000, but we'll be conservative
        
        while True:
            try:
                # Build API request
                params = {
                    'startIndex': start_index,
                    'resultsPerPage': results_per_page,
                    'pubStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                    'pubEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                    'modStartDate': start_date.strftime('%Y-%m-%dT%H:%M:%S.000'),
                    'modEndDate': end_date.strftime('%Y-%m-%dT%H:%M:%S.000')
                }
                
                # Make API request with rate limiting
                data = await self._make_api_request(params)
                
                if not data or 'vulnerabilities' not in data:
                    logger.warning("No vulnerability data received from API")
                    break
                
                vulnerabilities = data['vulnerabilities']
                if not vulnerabilities:
                    logger.info("No more vulnerabilities to process")
                    break
                
                # Process vulnerabilities
                await self._process_vulnerabilities(vulnerabilities)
                
                # Check if we have more pages
                total_results = data.get('totalResults', 0)
                start_index += results_per_page
                
                if start_index >= total_results:
                    logger.info(f"Processed all {total_results} results")
                    break
                
                logger.info(f"Processed {start_index}/{total_results} CVEs...")
                
            except Exception as e:
                logger.error(f"Error during CVE collection: {e}")
                self.stats["errors"] += 1
                break
        
        # Log final statistics
        logger.info(f"CVE Collection Complete:")
        logger.info(f"  Total requests: {self.stats['requests_made']}")
        logger.info(f"  CVEs processed: {self.stats['cves_processed']}")
        logger.info(f"  CVEs inserted: {self.stats['cves_inserted']}")
        logger.info(f"  CVEs updated: {self.stats['cves_updated']}")
        logger.info(f"  Errors: {self.stats['errors']}")
    
    async def collect_specific_cves(self, cve_ids: List[str]) -> None:
        """
        Collect specific CVEs by their IDs.
        
        Args:
            cve_ids: List of CVE IDs to collect
        """
        logger.info(f"Collecting {len(cve_ids)} specific CVEs")
        
        for cve_id in cve_ids:
            try:
                params = {'cveId': cve_id}
                data = await self._make_api_request(params)
                
                if data and 'vulnerabilities' in data:
                    await self._process_vulnerabilities(data['vulnerabilities'])
                
            except Exception as e:
                logger.error(f"Error collecting CVE {cve_id}: {e}")
                self.stats["errors"] += 1
        
        logger.info(f"Specific CVE collection complete")
    
    async def _make_api_request(self, params: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Make rate-limited API request to NVD.
        
        Args:
            params: Query parameters for the API request
            
        Returns:
            JSON response data or None if error
        """
        if not self.session:
            raise RuntimeError("Session not initialized")
        
        # Rate limiting
        await asyncio.sleep(self.request_delay)
        
        try:
            async with self.session.get(self.base_url, params=params) as response:
                self.stats["requests_made"] += 1
                
                if response.status == 200:
                    return await response.json()
                elif response.status == 403:
                    logger.error("API rate limit exceeded or access denied")
                    # Exponential backoff
                    await asyncio.sleep(60)
                    return None
                else:
                    logger.error(f"API request failed: {response.status}")
                    return None
                    
        except asyncio.TimeoutError:
            logger.error("API request timeout")
            return None
        except Exception as e:
            logger.error(f"API request error: {e}")
            return None
    
    async def _process_vulnerabilities(self, vulnerabilities: List[Dict[str, Any]]) -> None:
        """
        Process and store vulnerability data in the database.
        
        Args:
            vulnerabilities: List of vulnerability data from NVD API
        """
        async with db_manager.get_postgres_session() as session:
            adapter = PostgreSQLAdapter(session)
            
            for vuln_data in vulnerabilities:
                try:
                    cve_item = vuln_data.get('cve', {})
                    
                    # Extract basic CVE information
                    cve_record = await self._extract_cve_record(cve_item)
                    
                    if cve_record:
                        # Check if CVE already exists
                        existing = await adapter.get_cve_by_id(cve_record['cve_id'])
                        
                        if existing:
                            # Update existing record if modified date is newer
                            if self._is_newer_record(cve_record, existing):
                                await adapter.update_cve(existing.id, cve_record)
                                self.stats["cves_updated"] += 1
                                logger.debug(f"Updated CVE: {cve_record['cve_id']}")
                        else:
                            # Insert new record
                            await adapter.create_cve(cve_record)
                            self.stats["cves_inserted"] += 1
                            logger.debug(f"Inserted CVE: {cve_record['cve_id']}")
                        
                        self.stats["cves_processed"] += 1
                
                except Exception as e:
                    logger.error(f"Error processing vulnerability: {e}")
                    self.stats["errors"] += 1
    
    async def _extract_cve_record(self, cve_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Extract and normalize CVE record from NVD API data.
        
        Args:
            cve_data: Raw CVE data from API
            
        Returns:
            Normalized CVE record dictionary
        """
        try:
            # Basic information
            cve_id = cve_data.get('id', '')
            if not cve_id:
                logger.warning("CVE missing ID, skipping")
                return None
            
            # Description (English preferred)
            descriptions = cve_data.get('descriptions', [])
            description = ""
            for desc in descriptions:
                if desc.get('lang') == 'en':
                    description = desc.get('value', '')
                    break
            if not description and descriptions:
                description = descriptions[0].get('value', '')
            
            # CVSS metrics
            cvss_score = None
            cvss_vector = None
            severity = None
            
            metrics = cve_data.get('metrics', {})
            
            # Try CVSS v3.1 first, then v3.0, then v2.0
            for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                if version in metrics and metrics[version]:
                    metric = metrics[version][0]  # Take first metric
                    cvss_data = metric.get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    cvss_vector = cvss_data.get('vectorString')
                    severity = cvss_data.get('baseSeverity', '').lower()
                    break
            
            # Published and modified dates
            published_date = None
            modified_date = None
            
            if 'published' in cve_data:
                published_date = datetime.fromisoformat(cve_data['published'].replace('Z', '+00:00'))
            
            if 'lastModified' in cve_data:
                modified_date = datetime.fromisoformat(cve_data['lastModified'].replace('Z', '+00:00'))
            
            # Affected products/configurations
            affected_products = []
            configurations = cve_data.get('configurations', [])
            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_matches = node.get('cpeMatch', [])
                    for cpe in cpe_matches:
                        if cpe.get('vulnerable', False):
                            affected_products.append({
                                'cpe': cpe.get('criteria', ''),
                                'version_start': cpe.get('versionStartIncluding'),
                                'version_end': cpe.get('versionEndIncluding')
                            })
            
            # References
            references = []
            ref_data = cve_data.get('references', [])
            for ref in ref_data:
                references.append({
                    'url': ref.get('url', ''),
                    'source': ref.get('source', ''),
                    'tags': ref.get('tags', [])
                })
            
            # Build record
            record = {
                'cve_id': cve_id,
                'description': description,
                'cvss_score': cvss_score,
                'cvss_vector': cvss_vector,
                'severity': severity,
                'published_date': published_date,
                'modified_date': modified_date,
                'affected_products': affected_products if affected_products else None,
                'references': references if references else None,
                'exploit_available': False,  # Will be updated separately
                'patch_available': False     # Will be updated separately
            }
            
            return record
            
        except Exception as e:
            logger.error(f"Error extracting CVE record: {e}")
            return None
    
    def _is_newer_record(self, new_record: Dict[str, Any], existing_record) -> bool:
        """
        Check if new record is newer than existing record.
        
        Args:
            new_record: New CVE record data
            existing_record: Existing CVE record from database
            
        Returns:
            True if new record is newer
        """
        if not new_record.get('modified_date') or not existing_record.modified_date:
            return True  # Update if dates are missing
        
        return new_record['modified_date'] > existing_record.modified_date


async def main():
    """Main function to run CVE data collection."""
    
    # Initialize database
    await db_manager.initialize()
    
    try:
        # Create collector instance
        async with CVEDataCollector() as collector:
            
            # Collect recent CVEs (last 7 days by default)
            await collector.collect_recent_cves(days_back=7)
            
            # Optional: Collect specific high-profile CVEs
            # critical_cves = ['CVE-2024-1234', 'CVE-2024-5678']  # Example
            # await collector.collect_specific_cves(critical_cves)
    
    finally:
        # Clean up database connections
        await db_manager.close()


if __name__ == "__main__":
    # Create logs directory if it doesn't exist
    Path("logs").mkdir(exist_ok=True)
    
    # Run the collector
    asyncio.run(main())