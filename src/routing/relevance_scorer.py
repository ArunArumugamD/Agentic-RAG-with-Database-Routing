#!/usr/bin/env python3
"""
Improved Relevance Scoring System

This module provides realistic and transparent relevance scoring
without making false claims about accuracy or confidence.
"""

import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class RelevanceMetrics:
    """Transparent metrics for query result relevance"""
    relevance_score: float  # 0.0-1.0: How well results match the query
    source_reliability: float  # 0.0-1.0: Reliability of data sources
    data_freshness: float  # 0.0-1.0: How recent the data is
    result_diversity: float  # 0.0-1.0: Diversity of result types
    overall_score: float  # Weighted combination of above
    
    # Transparent explanations
    score_explanation: str
    limitations: List[str]
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "relevance_score": round(self.relevance_score, 3),
            "source_reliability": round(self.source_reliability, 3),
            "data_freshness": round(self.data_freshness, 3),
            "result_diversity": round(self.result_diversity, 3),
            "overall_score": round(self.overall_score, 3),
            "explanation": self.score_explanation,
            "limitations": self.limitations
        }


class ImprovedRelevanceScorer:
    """
    Calculates relevance scores based on multiple practical factors.
    
    This scorer is honest about its limitations and doesn't claim
    to measure true accuracy or confidence.
    """
    
    def __init__(self):
        # Source reliability weights (based on data source characteristics)
        self.source_weights = {
            "postgresql": 0.85,  # Structured, validated data
            "qdrant": 0.75,      # Semantic similarity, less structured
            "nvd_api": 0.95,     # Official CVE database
            "otx": 0.70,         # Community-driven intelligence
            "mitre": 0.90,       # Official MITRE data
            "sample_data": 0.30  # Sample/demo data
        }
        
        # Data type reliability
        self.data_type_weights = {
            "cve": 0.9,
            "ioc": 0.8,
            "threat_actor": 0.85,
            "malware": 0.8,
            "mitre_technique": 0.9
        }
    
    def calculate_relevance(
        self,
        query: str,
        results: List[Dict[str, Any]],
        sources_used: List[str],
        query_metadata: Dict[str, Any] = None
    ) -> RelevanceMetrics:
        """
        Calculate comprehensive relevance metrics.
        
        Args:
            query: Original user query
            results: Query results
            sources_used: Data sources that were queried
            query_metadata: Additional query context
        
        Returns:
            RelevanceMetrics with transparent scoring
        """
        if not results:
            return self._no_results_metrics()
        
        # Calculate component scores
        relevance_score = self._calculate_query_relevance(query, results)
        source_reliability = self._calculate_source_reliability(sources_used, results)
        data_freshness = self._calculate_data_freshness(results)
        result_diversity = self._calculate_result_diversity(results)
        
        # Calculate weighted overall score
        overall_score = (
            relevance_score * 0.40 +      # How well it matches the query
            source_reliability * 0.25 +   # How reliable the sources are
            data_freshness * 0.20 +       # How recent the data is
            result_diversity * 0.15       # How diverse the results are
        )
        
        # Generate explanation and limitations
        explanation = self._generate_explanation(
            relevance_score, source_reliability, data_freshness, result_diversity
        )
        limitations = self._generate_limitations(sources_used, len(results))
        
        return RelevanceMetrics(
            relevance_score=relevance_score,
            source_reliability=source_reliability,
            data_freshness=data_freshness,
            result_diversity=result_diversity,
            overall_score=overall_score,
            score_explanation=explanation,
            limitations=limitations
        )
    
    def _calculate_query_relevance(self, query: str, results: List[Dict[str, Any]]) -> float:
        """Calculate how well results match the query intent."""
        if not results:
            return 0.0
        
        # For vector search results, use similarity scores
        vector_scores = []
        structured_matches = 0
        
        for result in results:
            # Vector search results have similarity scores
            if "score" in result:
                vector_scores.append(result["score"])
            
            # Structured search results - check for exact matches
            content = str(result.get("content", "")).lower()
            query_lower = query.lower()
            
            # Simple keyword matching for structured results
            query_words = query_lower.split()
            matches = sum(1 for word in query_words if word in content)
            if matches > 0:
                structured_matches += matches / len(query_words)
        
        # Combine vector similarity and structured matches
        if vector_scores:
            avg_vector_score = sum(vector_scores) / len(vector_scores)
        else:
            avg_vector_score = 0.5  # Neutral score for non-vector results
        
        if structured_matches > 0:
            structured_score = min(structured_matches / len(results), 1.0)
        else:
            structured_score = 0.3  # Lower score for no keyword matches
        
        # Weighted combination
        return (avg_vector_score * 0.6 + structured_score * 0.4)
    
    def _calculate_source_reliability(self, sources_used: List[str], results: List[Dict[str, Any]]) -> float:
        """Calculate reliability based on data sources."""
        if not sources_used:
            return 0.5  # Neutral score if unknown
        
        # Get weighted average of source reliabilities
        total_weight = 0
        weighted_sum = 0
        
        for source in sources_used:
            weight = self.source_weights.get(source, 0.5)  # Default to neutral
            weighted_sum += weight
            total_weight += 1
        
        if total_weight == 0:
            return 0.5
        
        base_score = weighted_sum / total_weight
        
        # Bonus for multiple sources (cross-validation)
        if len(set(sources_used)) > 1:
            base_score = min(base_score * 1.1, 1.0)  # 10% bonus, cap at 1.0
        
        return base_score
    
    def _calculate_data_freshness(self, results: List[Dict[str, Any]]) -> float:
        """Calculate how recent the data is."""
        if not results:
            return 0.0
        
        current_time = datetime.utcnow()
        freshness_scores = []
        
        for result in results:
            # Try to find timestamp fields
            timestamp_fields = [
                "published_date", "last_modified", "created_at", 
                "first_seen", "last_seen", "collected_at"
            ]
            
            result_timestamp = None
            for field in timestamp_fields:
                if field in result:
                    try:
                        if isinstance(result[field], str):
                            result_timestamp = datetime.fromisoformat(result[field].replace('Z', '+00:00'))
                        elif isinstance(result[field], datetime):
                            result_timestamp = result[field]
                        break
                    except:
                        continue
            
            if result_timestamp:
                # Ensure both timestamps are timezone-aware for comparison
                if result_timestamp.tzinfo is None:
                    result_timestamp = result_timestamp.replace(tzinfo=timezone.utc)
                if current_time.tzinfo is None:
                    current_time = current_time.replace(tzinfo=timezone.utc)
                
                # Calculate age-based freshness (fresher = higher score)
                age_days = (current_time - result_timestamp).days
                
                if age_days <= 1:
                    freshness_scores.append(1.0)  # Very fresh
                elif age_days <= 7:
                    freshness_scores.append(0.9)  # Fresh
                elif age_days <= 30:
                    freshness_scores.append(0.7)  # Recent
                elif age_days <= 90:
                    freshness_scores.append(0.5)  # Somewhat recent
                elif age_days <= 365:
                    freshness_scores.append(0.3)  # Old
                else:
                    freshness_scores.append(0.1)  # Very old
            else:
                freshness_scores.append(0.5)  # Unknown age - neutral score
        
        return sum(freshness_scores) / len(freshness_scores) if freshness_scores else 0.5
    
    def _calculate_result_diversity(self, results: List[Dict[str, Any]]) -> float:
        """Calculate diversity of result types and sources."""
        if not results:
            return 0.0
        
        # Count different types of results
        result_types = set()
        content_sources = set()
        
        for result in results:
            # Check metadata for type indicators
            metadata = result.get("metadata", {})
            
            # Data type diversity
            if "type" in metadata:
                result_types.add(metadata["type"])
            elif "ioc_type" in metadata:
                result_types.add(metadata["ioc_type"])
            elif "CVE-" in str(result.get("content", "")):
                result_types.add("cve")
            
            # Source diversity
            if "source" in metadata:
                content_sources.add(metadata["source"])
            elif "source" in result:
                content_sources.add(result["source"])
        
        # Calculate diversity score
        type_diversity = min(len(result_types) / 5.0, 1.0)  # Normalize to max 5 types
        source_diversity = min(len(content_sources) / 3.0, 1.0)  # Normalize to max 3 sources
        
        return (type_diversity + source_diversity) / 2.0
    
    def _generate_explanation(
        self, 
        relevance: float, 
        reliability: float, 
        freshness: float, 
        diversity: float
    ) -> str:
        """Generate human-readable explanation of the score."""
        explanations = []
        
        if relevance >= 0.8:
            explanations.append("Results closely match your query")
        elif relevance >= 0.6:
            explanations.append("Results partially match your query")
        else:
            explanations.append("Results have limited relevance to your query")
        
        if reliability >= 0.8:
            explanations.append("Data comes from highly reliable sources")
        elif reliability >= 0.6:
            explanations.append("Data comes from moderately reliable sources")
        else:
            explanations.append("Data source reliability is limited")
        
        if freshness >= 0.8:
            explanations.append("Data is very recent")
        elif freshness >= 0.6:
            explanations.append("Data is reasonably recent")
        else:
            explanations.append("Data may be outdated")
        
        if diversity >= 0.7:
            explanations.append("Results cover diverse aspects of your query")
        elif diversity >= 0.4:
            explanations.append("Results have moderate diversity")
        else:
            explanations.append("Results are limited in scope")
        
        return ". ".join(explanations) + "."
    
    def _generate_limitations(self, sources_used: List[str], result_count: int) -> List[str]:
        """Generate honest limitations of the scoring."""
        limitations = [
            "Scores reflect data availability and source characteristics, not absolute accuracy",
            "Relevance is based on keyword matching and semantic similarity",
        ]
        
        if result_count < 5:
            limitations.append("Limited number of results may affect score reliability")
        
        if "sample_data" in sources_used:
            limitations.append("Some results include sample data for demonstration")
        
        if len(sources_used) == 1:
            limitations.append("Results from single source - no cross-validation")
        
        return limitations
    
    def _no_results_metrics(self) -> RelevanceMetrics:
        """Return metrics for when no results are found."""
        return RelevanceMetrics(
            relevance_score=0.0,
            source_reliability=0.0,
            data_freshness=0.0,
            result_diversity=0.0,
            overall_score=0.0,
            score_explanation="No results found for this query",
            limitations=[
                "Query may be too specific or data may not be available",
                "Try rephrasing the query or using broader terms"
            ]
        )


# Global scorer instance
relevance_scorer = ImprovedRelevanceScorer()