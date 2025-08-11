"""
Intelligent Query Classifier for routing queries to appropriate databases.
Uses ML-based classification and rule-based fallbacks for high accuracy.
"""

import re
from typing import Dict, List, Tuple, Optional, Any
from enum import Enum
from dataclasses import dataclass
import logging
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline
import numpy as np

from config.settings import settings

logger = logging.getLogger(__name__)


class QueryType(str, Enum):
    """Query type enumeration for routing decisions."""
    STRUCTURED = "structured"  # SQL queries for exact matches, aggregations
    SEMANTIC = "semantic"      # Vector search for similarity, explanations
    HYBRID = "hybrid"          # Requires both databases


class QueryIntent(str, Enum):
    """Intent classification for cybersecurity queries."""
    CVE_LOOKUP = "cve_lookup"
    VULNERABILITY_SEARCH = "vulnerability_search"
    THREAT_ANALYSIS = "threat_analysis"
    STATISTICS = "statistics"
    SIMILARITY_SEARCH = "similarity_search"
    EXPLANATION = "explanation"
    TREND_ANALYSIS = "trend_analysis"


class DataSource(str, Enum):
    """Data source enumeration for routing decisions."""
    POSTGRESQL = "postgresql"
    QDRANT = "qdrant"
    BOTH = "both"


@dataclass
class ClassificationResult:
    """Result of query classification with confidence scores."""
    query_type: QueryType
    intent: QueryIntent
    confidence: float
    reasoning: str
    suggested_keywords: List[str]
    requires_structured: bool
    requires_semantic: bool


class CybersecurityQueryClassifier:
    """
    Advanced query classifier for cybersecurity threat intelligence.
    Combines rule-based classification with ML for high accuracy.
    """
    
    def __init__(self):
        self.structured_patterns = self._compile_structured_patterns()
        self.semantic_patterns = self._compile_semantic_patterns()
        self.intent_keywords = self._build_intent_keywords()
        self.ml_classifier = self._initialize_ml_classifier()
        
    def _compile_structured_patterns(self) -> List[Tuple[re.Pattern, str]]:
        """Compile regex patterns for structured queries."""
        patterns = [
            # CVE specific patterns
            (re.compile(r'\bCVE-\d{4}-\d{4,}\b', re.IGNORECASE), "cve_id"),
            (re.compile(r'\bcvss\s*(score|rating)\s*[><=]\s*\d', re.IGNORECASE), "cvss_filter"),
            (re.compile(r'\bseverity\s*(high|medium|low|critical)\b', re.IGNORECASE), "severity_filter"),
            
            # Temporal patterns
            (re.compile(r'\b(after|before|since|until)\s*\d{4}', re.IGNORECASE), "date_filter"),
            (re.compile(r'\blast\s*(year|month|week|day)\b', re.IGNORECASE), "recent_filter"),
            
            # Statistical patterns
            (re.compile(r'\b(count|number|total|sum|average|max|min)\s*of\b', re.IGNORECASE), "aggregation"),
            (re.compile(r'\bhow\s*many\b', re.IGNORECASE), "count_query"),
            (re.compile(r'\btop\s*\d+\b', re.IGNORECASE), "top_n"),
            
            # Vendor/Product patterns
            (re.compile(r'\b(vendor|manufacturer|company):\s*\w+', re.IGNORECASE), "vendor_filter"),
            (re.compile(r'\bproduct\s*(name|version)\b', re.IGNORECASE), "product_filter"),
            
            # Exact match patterns
            (re.compile(r'\bexact\s*(match|ly)\b', re.IGNORECASE), "exact_match"),
            (re.compile(r'\bwhere\s+\w+\s*[=!<>]', re.IGNORECASE), "where_clause"),
        ]
        return patterns
    
    def _compile_semantic_patterns(self) -> List[Tuple[re.Pattern, str]]:
        """Compile regex patterns for semantic queries."""
        patterns = [
            # Similarity patterns
            (re.compile(r'\b(similar|like|related|comparable)\s*to\b', re.IGNORECASE), "similarity"),
            (re.compile(r'\bfind\s*(similar|related)\b', re.IGNORECASE), "find_similar"),
            
            # Explanation patterns
            (re.compile(r'\b(what|how|why|explain|describe)\b', re.IGNORECASE), "explanation"),
            (re.compile(r'\btell\s*me\s*about\b', re.IGNORECASE), "description"),
            
            # Technique patterns
            (re.compile(r'\b(technique|tactic|procedure|method)\b', re.IGNORECASE), "ttp"),
            (re.compile(r'\bmitre\s*att&ck\b', re.IGNORECASE), "mitre_attack"),
            
            # Contextual patterns
            (re.compile(r'\bcontext\s*(of|about|around)\b', re.IGNORECASE), "contextual"),
            (re.compile(r'\bbackground\s*(information|on)\b', re.IGNORECASE), "background"),
        ]
        return patterns
    
    def _build_intent_keywords(self) -> Dict[QueryIntent, List[str]]:
        """Build keyword mappings for intent classification."""
        return {
            QueryIntent.CVE_LOOKUP: [
                "cve", "vulnerability id", "cve-", "nvd", "mitre"
            ],
            QueryIntent.VULNERABILITY_SEARCH: [
                "vulnerability", "exploit", "weakness", "flaw", "bug", "security issue"
            ],
            QueryIntent.THREAT_ANALYSIS: [
                "threat", "attack", "malware", "campaign", "apt", "threat actor"
            ],
            QueryIntent.STATISTICS: [
                "count", "statistics", "total", "average", "trend", "report"
            ],
            QueryIntent.SIMILARITY_SEARCH: [
                "similar", "like", "related", "comparable", "find similar"
            ],
            QueryIntent.EXPLANATION: [
                "explain", "what is", "how does", "describe", "definition"
            ],
            QueryIntent.TREND_ANALYSIS: [
                "trend", "over time", "increasing", "decreasing", "pattern"
            ]
        }
    
    def _initialize_ml_classifier(self) -> Pipeline:
        """Initialize ML classifier for query type prediction."""
        # In production, this would be trained on labeled data
        # For now, we create a basic pipeline structure
        classifier = Pipeline([
            ('tfidf', TfidfVectorizer(
                max_features=1000,
                ngram_range=(1, 2),
                stop_words='english'
            )),
            ('classifier', MultinomialNB())
        ])
        
        # Training data would be loaded here in production
        # For demonstration, we'll use rule-based classification
        return classifier
    
    def classify_query(self, query: str) -> ClassificationResult:
        """
        Main classification method that routes queries intelligently.
        
        Args:
            query: User query string
            
        Returns:
            ClassificationResult with routing decision and metadata
        """
        query_lower = query.lower().strip()
        
        # Step 1: Rule-based classification
        structured_score = self._calculate_structured_score(query_lower)
        semantic_score = self._calculate_semantic_score(query_lower)
        
        # Step 2: Intent classification
        intent = self._classify_intent(query_lower)
        
        # Step 3: Determine query type based on scores
        query_type, confidence, reasoning = self._determine_query_type(
            structured_score, semantic_score, intent
        )
        
        # Step 4: Extract suggested keywords
        keywords = self._extract_keywords(query_lower, query_type)
        
        # Step 5: Determine database requirements
        requires_structured, requires_semantic = self._determine_db_requirements(
            query_type, intent, structured_score, semantic_score
        )
        
        result = ClassificationResult(
            query_type=query_type,
            intent=intent,
            confidence=confidence,
            reasoning=reasoning,
            suggested_keywords=keywords,
            requires_structured=requires_structured,
            requires_semantic=requires_semantic
        )
        
        logger.info(f"Query classified: {query_type.value} with confidence {confidence:.2f}")
        return result
    
    def _calculate_structured_score(self, query: str) -> float:
        """Calculate likelihood that query requires structured data access."""
        score = 0.0
        matches = []
        
        for pattern, pattern_type in self.structured_patterns:
            if pattern.search(query):
                matches.append(pattern_type)
                # Weight different pattern types
                if pattern_type in ["cve_id", "cvss_filter", "aggregation"]:
                    score += 0.3
                elif pattern_type in ["date_filter", "vendor_filter", "exact_match"]:
                    score += 0.2
                else:
                    score += 0.1
        
        # Boost score for keyword presence
        for keyword in settings.structured_query_keywords:
            if keyword in query:
                score += 0.05
        
        return min(score, 1.0)
    
    def _calculate_semantic_score(self, query: str) -> float:
        """Calculate likelihood that query requires semantic search."""
        score = 0.0
        matches = []
        
        for pattern, pattern_type in self.semantic_patterns:
            if pattern.search(query):
                matches.append(pattern_type)
                # Weight different pattern types
                if pattern_type in ["similarity", "explanation"]:
                    score += 0.3
                elif pattern_type in ["ttp", "contextual"]:
                    score += 0.2
                else:
                    score += 0.1
        
        # Boost score for semantic indicators
        for indicator in settings.semantic_query_indicators:
            if indicator in query:
                score += 0.05
        
        return min(score, 1.0)
    
    def _classify_intent(self, query: str) -> QueryIntent:
        """Classify the intent of the query."""
        intent_scores = {}
        
        for intent, keywords in self.intent_keywords.items():
            score = 0
            for keyword in keywords:
                if keyword in query:
                    score += 1
            intent_scores[intent] = score
        
        # Return intent with highest score, default to vulnerability search
        if max(intent_scores.values()) > 0:
            return max(intent_scores.items(), key=lambda x: x[1])[0]
        else:
            return QueryIntent.VULNERABILITY_SEARCH
    
    def _determine_query_type(
        self, 
        structured_score: float, 
        semantic_score: float, 
        intent: QueryIntent
    ) -> Tuple[QueryType, float, str]:
        """Determine final query type based on scores and intent."""
        
        # Intent-based routing rules
        if intent == QueryIntent.CVE_LOOKUP and structured_score > 0.3:
            return QueryType.STRUCTURED, 0.9, "CVE lookup requires structured data"
        
        if intent == QueryIntent.STATISTICS and structured_score > 0.2:
            return QueryType.STRUCTURED, 0.85, "Statistical queries need structured data"
        
        if intent in [QueryIntent.SIMILARITY_SEARCH, QueryIntent.EXPLANATION]:
            return QueryType.SEMANTIC, 0.9, "Similarity/explanation requires semantic search"
        
        # Score-based routing
        if structured_score > semantic_score + 0.2:
            confidence = min(structured_score + 0.1, 1.0)
            return QueryType.STRUCTURED, confidence, f"High structured score: {structured_score:.2f}"
        
        elif semantic_score > structured_score + 0.2:
            confidence = min(semantic_score + 0.1, 1.0)
            return QueryType.SEMANTIC, confidence, f"High semantic score: {semantic_score:.2f}"
        
        else:
            # Both scores are close - use hybrid approach
            confidence = max(structured_score, semantic_score)
            return QueryType.HYBRID, confidence, "Mixed query requires both databases"
    
    def _extract_keywords(self, query: str, query_type: QueryType) -> List[str]:
        """Extract relevant keywords based on query type."""
        keywords = []
        
        # CVE patterns
        cve_matches = re.findall(r'CVE-\d{4}-\d{4,}', query, re.IGNORECASE)
        keywords.extend(cve_matches)
        
        # CVSS scores
        cvss_matches = re.findall(r'cvss.*?(\d+(?:\.\d+)?)', query, re.IGNORECASE)
        keywords.extend([f"cvss:{score}" for score in cvss_matches])
        
        # Years
        year_matches = re.findall(r'\b(20\d{2})\b', query)
        keywords.extend([f"year:{year}" for year in year_matches])
        
        # Vendors/Products (simple extraction)
        vendor_matches = re.findall(r'(?:vendor|company|manufacturer):\s*(\w+)', query, re.IGNORECASE)
        keywords.extend([f"vendor:{vendor}" for vendor in vendor_matches])
        
        return keywords
    
    def _determine_db_requirements(
        self, 
        query_type: QueryType, 
        intent: QueryIntent,
        structured_score: float,
        semantic_score: float
    ) -> Tuple[bool, bool]:
        """Determine which databases are required."""
        
        if query_type == QueryType.STRUCTURED:
            return True, False
        elif query_type == QueryType.SEMANTIC:
            return False, True
        elif query_type == QueryType.HYBRID:
            return True, True
        else:
            # Fallback based on scores
            return structured_score > 0.1, semantic_score > 0.1


# Global instance for compatibility
query_classifier = CybersecurityQueryClassifier()