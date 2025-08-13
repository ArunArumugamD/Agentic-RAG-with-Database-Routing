from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_, or_, desc, asc, update
from sqlalchemy.orm import selectinload
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
import logging

from .schemas import (
    CVERecord, MitreAttackTechnique, ThreatActor, MalwareFamily,
    ThreatCampaign, VulnerabilityExploit, IOC, QueryLog
)

logger = logging.getLogger(__name__)


class PostgreSQLAdapter:
    """Optimized PostgreSQL queries for threat intelligence"""
    
    def __init__(self, session: AsyncSession):
        self.session = session
    
    async def search_cves(
        self,
        query: str,
        severity: Optional[str] = None,
        min_score: Optional[float] = None,
        exploit_available: Optional[bool] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Search CVE records with filters"""
        try:
            stmt = select(CVERecord)
            
            # Text search in description
            if query:
                stmt = stmt.where(
                    or_(
                        CVERecord.cve_id.ilike(f"%{query}%"),
                        CVERecord.description.ilike(f"%{query}%")
                    )
                )
            
            # Apply filters
            if severity:
                stmt = stmt.where(CVERecord.severity == severity)
            if min_score is not None:
                stmt = stmt.where(CVERecord.cvss_score >= min_score)
            if exploit_available is not None:
                stmt = stmt.where(CVERecord.exploit_available == exploit_available)
            
            # Order by severity and date
            stmt = stmt.order_by(
                desc(CVERecord.cvss_score),
                desc(CVERecord.published_date)
            ).limit(limit)
            
            result = await self.session.execute(stmt)
            cves = result.scalars().all()
            
            return [self._cve_to_dict(cve) for cve in cves]
            
        except Exception as e:
            logger.error(f"CVE search failed: {e}")
            raise
    
    async def search_mitre_techniques(
        self,
        query: str,
        tactic: Optional[str] = None,
        platform: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Search MITRE ATT&CK techniques"""
        try:
            stmt = select(MitreAttackTechnique)
            
            # Text search
            if query:
                stmt = stmt.where(
                    or_(
                        MitreAttackTechnique.technique_id.ilike(f"%{query}%"),
                        MitreAttackTechnique.name.ilike(f"%{query}%"),
                        MitreAttackTechnique.description.ilike(f"%{query}%")
                    )
                )
            
            # Apply filters
            if tactic:
                stmt = stmt.where(MitreAttackTechnique.tactic.ilike(f"%{tactic}%"))
                
            if platform:
                stmt = stmt.where(
                    MitreAttackTechnique.platforms.contains([platform])
                )
            
            stmt = stmt.order_by(MitreAttackTechnique.technique_id).limit(limit)
            
            result = await self.session.execute(stmt)
            techniques = result.scalars().all()
            
            return [self._technique_to_dict(tech) for tech in techniques]
            
        except Exception as e:
            logger.error(f"MITRE technique search failed: {e}")
            raise
    
    async def search_threat_actors(
        self,
        query: str,
        country: Optional[str] = None,
        motivation: Optional[str] = None,
        active_only: bool = True,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Search threat actors"""
        try:
            stmt = select(ThreatActor).options(selectinload(ThreatActor.campaigns))
            
            # Text search
            if query:
                stmt = stmt.where(
                    or_(
                        ThreatActor.name.ilike(f"%{query}%"),
                        ThreatActor.description.ilike(f"%{query}%")
                    )
                )
            
            # Apply filters
            if country:
                stmt = stmt.where(ThreatActor.origin_country.ilike(f"%{country}%"))
            if motivation:
                stmt = stmt.where(ThreatActor.motivation.ilike(f"%{motivation}%"))
            if active_only:
                stmt = stmt.where(ThreatActor.active_status == True)
            
            stmt = stmt.order_by(desc(ThreatActor.last_seen)).limit(limit)
            
            result = await self.session.execute(stmt)
            actors = result.scalars().all()
            
            return [self._actor_to_dict(actor) for actor in actors]
            
        except Exception as e:
            logger.error(f"Threat actor search failed: {e}")
            raise
    
    async def search_malware(
        self,
        query: str,
        malware_type: Optional[str] = None,
        platform: Optional[str] = None,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Search malware families"""
        try:
            stmt = select(MalwareFamily)
            
            # Text search
            if query:
                stmt = stmt.where(
                    or_(
                        MalwareFamily.name.ilike(f"%{query}%"),
                        MalwareFamily.description.ilike(f"%{query}%")
                    )
                )
            
            # Apply filters
            if malware_type:
                stmt = stmt.where(MalwareFamily.type.ilike(f"%{malware_type}%"))
            if platform:
                stmt = stmt.where(MalwareFamily.platform.ilike(f"%{platform}%"))
            
            stmt = stmt.order_by(desc(MalwareFamily.last_seen)).limit(limit)
            
            result = await self.session.execute(stmt)
            malware = result.scalars().all()
            
            return [self._malware_to_dict(mal) for mal in malware]
            
        except Exception as e:
            logger.error(f"Malware search failed: {e}")
            raise
    
    async def get_vulnerability_exploits(
        self,
        cve_id: str
    ) -> List[Dict[str, Any]]:
        """Get exploitation information for a CVE"""
        try:
            stmt = select(VulnerabilityExploit).where(
                VulnerabilityExploit.cve_id == cve_id
            ).order_by(desc(VulnerabilityExploit.first_seen))
            
            result = await self.session.execute(stmt)
            exploits = result.scalars().all()
            
            return [self._exploit_to_dict(exploit) for exploit in exploits]
            
        except Exception as e:
            logger.error(f"Exploit search failed: {e}")
            raise
    
    async def search_iocs(
        self,
        query: str,
        ioc_type: Optional[str] = None,
        threat_type: Optional[str] = None,
        active_only: bool = True,
        limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Search IOCs (Indicators of Compromise)"""
        try:
            stmt = select(IOC)
            
            # Text search
            if query:
                stmt = stmt.where(
                    or_(
                        IOC.value.ilike(f"%{query}%"),
                        IOC.description.ilike(f"%{query}%")
                    )
                )
            
            # Apply filters
            if ioc_type:
                stmt = stmt.where(IOC.type == ioc_type)
            if threat_type:
                stmt = stmt.where(IOC.threat_type.ilike(f"%{threat_type}%"))
            if active_only:
                stmt = stmt.where(IOC.active == True)
            
            stmt = stmt.order_by(desc(IOC.last_seen)).limit(limit)
            
            result = await self.session.execute(stmt)
            iocs = result.scalars().all()
            
            return [self._ioc_to_dict(ioc) for ioc in iocs]
            
        except Exception as e:
            logger.error(f"IOC search failed: {e}")
            raise
    
    async def get_threat_landscape_summary(
        self,
        days_back: int = 30
    ) -> Dict[str, Any]:
        """Get threat landscape summary"""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days_back)
            
            # Critical CVEs count
            critical_cves = await self.session.execute(
                select(func.count(CVERecord.id)).where(
                    and_(
                        CVERecord.severity == "CRITICAL",
                        CVERecord.published_date >= cutoff_date
                    )
                )
            )
            
            # Exploited vulnerabilities
            exploited_cves = await self.session.execute(
                select(func.count(CVERecord.id)).where(
                    and_(
                        CVERecord.exploit_available == True,
                        CVERecord.published_date >= cutoff_date
                    )
                )
            )
            
            # Active threat actors
            active_actors = await self.session.execute(
                select(func.count(ThreatActor.id)).where(
                    and_(
                        ThreatActor.active_status == True,
                        ThreatActor.last_seen >= cutoff_date
                    )
                )
            )
            
            # Recent IOCs
            recent_iocs = await self.session.execute(
                select(func.count(IOC.id)).where(
                    and_(
                        IOC.active == True,
                        IOC.first_seen >= cutoff_date
                    )
                )
            )
            
            return {
                "period_days": days_back,
                "critical_cves": critical_cves.scalar() or 0,
                "exploited_vulnerabilities": exploited_cves.scalar() or 0,
                "active_threat_actors": active_actors.scalar() or 0,
                "recent_iocs": recent_iocs.scalar() or 0,
                "generated_at": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Threat landscape summary failed: {e}")
            raise
    
    async def log_query(
        self,
        query_text: str,
        query_type: str,
        route_taken: str,
        response_time_ms: int,
        result_count: int,
        confidence_score: float,
        self_correction_triggered: bool = False
    ) -> None:
        """Log query for analytics"""
        try:
            query_log = QueryLog(
                query_text=query_text,
                query_type=query_type,
                route_taken=route_taken,
                response_time_ms=response_time_ms,
                result_count=result_count,
                confidence_score=confidence_score,
                self_correction_triggered=self_correction_triggered
            )
            
            self.session.add(query_log)
            await self.session.commit()
            
        except Exception as e:
            logger.error(f"Query logging failed: {e}")
    
    # Utility methods for data serialization
    def _cve_to_dict(self, cve: CVERecord) -> Dict[str, Any]:
        return {
            "cve_id": cve.cve_id,
            "description": cve.description,
            "cvss_score": cve.cvss_score,
            "severity": cve.severity,
            "published_date": cve.published_date.isoformat() if cve.published_date else None,
            "exploit_available": cve.exploit_available,
            "patch_available": cve.patch_available,
            "affected_products": cve.affected_products
        }
    
    def _technique_to_dict(self, tech: MitreAttackTechnique) -> Dict[str, Any]:
        return {
            "technique_id": tech.technique_id,
            "name": tech.name,
            "description": tech.description,
            "tactic": tech.tactic,
            "platforms": tech.platforms,
            "data_sources": tech.data_sources,
            "detection": tech.detection,
            "mitigation": tech.mitigation
        }
    
    def _actor_to_dict(self, actor: ThreatActor) -> Dict[str, Any]:
        return {
            "name": actor.name,
            "aliases": actor.aliases,
            "description": actor.description,
            "origin_country": actor.origin_country,
            "motivation": actor.motivation,
            "sophistication": actor.sophistication,
            "target_industries": actor.target_industries,
            "techniques_used": actor.techniques_used,
            "active_status": actor.active_status,
            "campaign_count": len(actor.campaigns) if hasattr(actor, 'campaigns') else 0
        }
    
    def _malware_to_dict(self, malware: MalwareFamily) -> Dict[str, Any]:
        return {
            "name": malware.name,
            "type": malware.type,
            "description": malware.description,
            "platform": malware.platform,
            "capabilities": malware.capabilities,
            "associated_actors": malware.associated_actors,
            "kill_chain_phases": malware.kill_chain_phases
        }
    
    # CVE management methods for data collection
    async def get_cve_by_id(self, cve_id: str) -> Optional[CVERecord]:
        """Get a CVE record by its ID."""
        try:
            result = await self.session.execute(
                select(CVERecord).where(CVERecord.cve_id == cve_id)
            )
            return result.scalar_one_or_none()
        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
            return None
    
    async def create_cve(self, cve_data: Dict[str, Any]) -> Optional[CVERecord]:
        """Create a new CVE record."""
        try:
            # Fix field name mismatches between collection script and schema
            cve_data_fixed = cve_data.copy()
            
            if 'has_exploit' in cve_data_fixed:
                cve_data_fixed['exploit_available'] = cve_data_fixed.pop('has_exploit')
            if 'has_patch' in cve_data_fixed:
                cve_data_fixed['patch_available'] = cve_data_fixed.pop('has_patch')
            
            # Convert string dates to datetime objects (timezone-naive for PostgreSQL)
            from datetime import datetime
            date_fields = ['published_date', 'modified_date']
            for field in date_fields:
                if field in cve_data_fixed and isinstance(cve_data_fixed[field], str):
                    try:
                        # Parse ISO format dates and convert to timezone-naive
                        dt_str = cve_data_fixed[field].replace('Z', '+00:00')
                        dt_aware = datetime.fromisoformat(dt_str)
                        # Convert to timezone-naive UTC for PostgreSQL
                        cve_data_fixed[field] = dt_aware.replace(tzinfo=None)
                    except (ValueError, AttributeError):
                        # If parsing fails, set to None
                        cve_data_fixed[field] = None
            
            cve = CVERecord(**cve_data_fixed)
            self.session.add(cve)
            await self.session.flush()
            await self.session.refresh(cve)
            return cve
        except Exception as e:
            logger.error(f"Error creating CVE {cve_data.get('cve_id', 'unknown')}: {e}")
            await self.session.rollback()
            return None
    
    async def update_cve(self, cve_id: int, cve_data: Dict[str, Any]) -> bool:
        """Update an existing CVE record."""
        try:
            await self.session.execute(
                update(CVERecord)
                .where(CVERecord.id == cve_id)
                .values(**cve_data)
            )
            return True
        except Exception as e:
            logger.error(f"Error updating CVE {cve_id}: {e}")
            await self.session.rollback()
            return False
    
    def _exploit_to_dict(self, exploit: VulnerabilityExploit) -> Dict[str, Any]:
        return {
            "exploit_name": exploit.exploit_name,
            "exploit_type": exploit.exploit_type,
            "complexity": exploit.complexity,
            "public_availability": exploit.public_availability,
            "weaponized": exploit.weaponized,
            "observed_in_wild": exploit.observed_in_wild,
            "first_seen": exploit.first_seen.isoformat() if exploit.first_seen else None
        }
    
    def _ioc_to_dict(self, ioc: IOC) -> Dict[str, Any]:
        return {
            "value": ioc.value,
            "type": ioc.type,
            "description": ioc.description,
            "confidence": ioc.confidence,
            "threat_type": ioc.threat_type,
            "associated_malware": ioc.associated_malware,
            "associated_actors": ioc.associated_actors,
            "tags": ioc.tags,
            "active": ioc.active
        }