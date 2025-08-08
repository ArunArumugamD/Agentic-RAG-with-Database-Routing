from sqlalchemy import Column, Integer, String, Text, DateTime, Float, Boolean, JSON, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from datetime import datetime

Base = declarative_base()


class CVERecord(Base):
    """CVE (Common Vulnerabilities and Exposures) records"""
    __tablename__ = "cve_records"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), unique=True, nullable=False, index=True)
    description = Column(Text, nullable=False)
    cvss_score = Column(Float, nullable=True, index=True)
    cvss_vector = Column(String(200), nullable=True)
    severity = Column(String(20), nullable=True, index=True)
    published_date = Column(DateTime, nullable=True, index=True)
    modified_date = Column(DateTime, nullable=True)
    affected_products = Column(JSON, nullable=True)
    references = Column(JSON, nullable=True)
    exploit_available = Column(Boolean, default=False, index=True)
    patch_available = Column(Boolean, default=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_cve_severity_score', 'severity', 'cvss_score'),
        Index('idx_cve_date_severity', 'published_date', 'severity'),
    )


class MitreAttackTechnique(Base):
    """MITRE ATT&CK Framework techniques"""
    __tablename__ = "mitre_techniques"
    
    id = Column(Integer, primary_key=True, index=True)
    technique_id = Column(String(20), unique=True, nullable=False, index=True)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    tactic = Column(String(100), nullable=True, index=True)
    sub_technique_of = Column(String(20), nullable=True)
    platforms = Column(JSON, nullable=True)
    permissions_required = Column(JSON, nullable=True)
    data_sources = Column(JSON, nullable=True)
    defenses_bypassed = Column(JSON, nullable=True)
    detection = Column(Text, nullable=True)
    mitigation = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_mitre_tactic_platform', 'tactic'),
    )


class ThreatActor(Base):
    """Threat actor/group profiles"""
    __tablename__ = "threat_actors"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    aliases = Column(JSON, nullable=True)
    description = Column(Text, nullable=False)
    origin_country = Column(String(100), nullable=True, index=True)
    motivation = Column(String(100), nullable=True, index=True)
    sophistication = Column(String(50), nullable=True, index=True)
    first_seen = Column(DateTime, nullable=True, index=True)
    last_seen = Column(DateTime, nullable=True, index=True)
    target_industries = Column(JSON, nullable=True)
    target_countries = Column(JSON, nullable=True)
    techniques_used = Column(JSON, nullable=True)
    tools_used = Column(JSON, nullable=True)
    active_status = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class MalwareFamily(Base):
    """Malware family information"""
    __tablename__ = "malware_families"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    type = Column(String(100), nullable=True, index=True)
    description = Column(Text, nullable=False)
    aliases = Column(JSON, nullable=True)
    platform = Column(String(100), nullable=True, index=True)
    capabilities = Column(JSON, nullable=True)
    first_seen = Column(DateTime, nullable=True, index=True)
    last_seen = Column(DateTime, nullable=True, index=True)
    associated_actors = Column(JSON, nullable=True)
    iocs = Column(JSON, nullable=True)
    kill_chain_phases = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class ThreatCampaign(Base):
    """Threat campaigns and operations"""
    __tablename__ = "threat_campaigns"
    
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False, index=True)
    description = Column(Text, nullable=False)
    actor_id = Column(Integer, ForeignKey("threat_actors.id"), nullable=True)
    start_date = Column(DateTime, nullable=True, index=True)
    end_date = Column(DateTime, nullable=True)
    target_industries = Column(JSON, nullable=True)
    target_countries = Column(JSON, nullable=True)
    techniques = Column(JSON, nullable=True)
    malware_used = Column(JSON, nullable=True)
    objectives = Column(JSON, nullable=True)
    status = Column(String(50), nullable=True, index=True)
    confidence = Column(String(20), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    actor = relationship("ThreatActor", back_populates="campaigns")


class VulnerabilityExploit(Base):
    """Vulnerability exploitation records"""
    __tablename__ = "vulnerability_exploits"
    
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String(50), ForeignKey("cve_records.cve_id"), nullable=False)
    exploit_name = Column(String(200), nullable=True)
    exploit_type = Column(String(100), nullable=True, index=True)
    complexity = Column(String(20), nullable=True, index=True)
    public_availability = Column(Boolean, default=False, index=True)
    metasploit_module = Column(Boolean, default=False)
    weaponized = Column(Boolean, default=False, index=True)
    observed_in_wild = Column(Boolean, default=False, index=True)
    first_seen = Column(DateTime, nullable=True, index=True)
    source_urls = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    cve = relationship("CVERecord", back_populates="exploits")


class IOC(Base):
    """Indicators of Compromise"""
    __tablename__ = "iocs"
    
    id = Column(Integer, primary_key=True, index=True)
    value = Column(String(500), nullable=False, index=True)
    type = Column(String(50), nullable=False, index=True)
    description = Column(Text, nullable=True)
    confidence = Column(String(20), nullable=True, index=True)
    threat_type = Column(String(100), nullable=True, index=True)
    first_seen = Column(DateTime, nullable=True, index=True)
    last_seen = Column(DateTime, nullable=True, index=True)
    source = Column(String(200), nullable=True)
    tags = Column(JSON, nullable=True)
    associated_malware = Column(JSON, nullable=True)
    associated_actors = Column(JSON, nullable=True)
    active = Column(Boolean, default=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    __table_args__ = (
        Index('idx_ioc_type_active', 'type', 'active'),
        Index('idx_ioc_threat_confidence', 'threat_type', 'confidence'),
    )


class QueryLog(Base):
    """Query performance and routing logs"""
    __tablename__ = "query_logs"
    
    id = Column(Integer, primary_key=True, index=True)
    query_text = Column(Text, nullable=False)
    query_type = Column(String(50), nullable=True, index=True)
    route_taken = Column(String(100), nullable=True, index=True)
    response_time_ms = Column(Integer, nullable=True, index=True)
    result_count = Column(Integer, nullable=True)
    confidence_score = Column(Float, nullable=True)
    user_feedback = Column(String(20), nullable=True)
    self_correction_triggered = Column(Boolean, default=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    
    __table_args__ = (
        Index('idx_query_performance', 'route_taken', 'response_time_ms'),
        Index('idx_query_timestamp', 'timestamp'),
    )


# Set up relationships
ThreatActor.campaigns = relationship("ThreatCampaign", back_populates="actor")
CVERecord.exploits = relationship("VulnerabilityExploit", back_populates="cve")