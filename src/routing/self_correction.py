"""
Advanced self-correction mechanisms for intelligent query routing.
Implements sophisticated result grading, query reformulation, and adaptive strategies.
"""

import logging
import json
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
import asyncio

from src.utils.llm_service import llm_service

logger = logging.getLogger(__name__)


class CorrectionStrategy(Enum):
    """Self-correction strategies"""
    EXPAND_SOURCES = "expand_sources"
    RELAX_FILTERS = "relax_filters"
    REFORMULATE_QUERY = "reformulate_query"
    DECOMPOSE_QUERY = "decompose_query"
    USE_SYNONYMS = "use_synonyms"
    TEMPORAL_ADJUSTMENT = "temporal_adjustment"
    CONTEXT_ENRICHMENT = "context_enrichment"


@dataclass
class GradingResult:
    """Result from relevance grading"""
    relevance_score: float
    completeness_score: float
    accuracy_confidence: float
    issues: List[str]
    suggestions: List[str]


class AdvancedSelfCorrector:
    """
    Advanced self-correction system for query routing.
    Uses DeepSeek R1's reasoning capabilities for intelligent correction.
    """
    
    def __init__(self):
        self.relevance_threshold = 0.7
        self.completeness_threshold = 0.6
        self.max_corrections = 3
        self.correction_history = []
    
    async def grade_results(
        self,
        query: str,
        results: List[Dict[str, Any]],
        expected_type: str = None
    ) -> GradingResult:
        """
        Perform comprehensive grading of query results.
        Uses multiple factors to assess quality.
        """
        if not results:
            return GradingResult(
                relevance_score=0.0,
                completeness_score=0.0,
                accuracy_confidence=0.0,
                issues=["No results returned"],
                suggestions=["Expand search", "Reformulate query"]
            )
        
        # Prepare results summary for analysis
        results_summary = self._prepare_results_summary(results)
        
        # Use LLM for comprehensive grading
        grading_prompt = f"""<think>
I need to evaluate these cybersecurity search results for relevance and completeness.
Let me analyze:
1. Do the results directly answer the query?
2. Is critical information missing?
3. Are the results accurate and current?
4. What issues exist?
</think>

Analyze these search results for a cybersecurity query:

Query: "{query}"
Expected Type: {expected_type or "general"}

Results Summary:
{json.dumps(results_summary, indent=2)}

Evaluate on these criteria:
1. Relevance (0.0-1.0): How well do results match the query intent?
2. Completeness (0.0-1.0): Is all necessary information present?
3. Accuracy Confidence (0.0-1.0): How confident are you in the accuracy?
4. Issues: List any problems found
5. Suggestions: List improvement strategies

Respond in JSON format:
{{
    "relevance_score": 0.0-1.0,
    "completeness_score": 0.0-1.0,
    "accuracy_confidence": 0.0-1.0,
    "issues": ["issue1", "issue2"],
    "suggestions": ["suggestion1", "suggestion2"]
}}
"""
        
        try:
            response = await llm_service.generate_response(
                grading_prompt,
                temperature=0.1,
                max_tokens=300
            )
            
            # Parse response
            grading_data = self._parse_json_response(response)
            
            return GradingResult(
                relevance_score=float(grading_data.get("relevance_score", 0.5)),
                completeness_score=float(grading_data.get("completeness_score", 0.5)),
                accuracy_confidence=float(grading_data.get("accuracy_confidence", 0.5)),
                issues=grading_data.get("issues", []),
                suggestions=grading_data.get("suggestions", [])
            )
            
        except Exception as e:
            logger.error(f"Grading failed: {e}")
            # Fallback to simple grading
            return self._simple_grade(results)
    
    async def generate_corrections(
        self,
        query: str,
        grading: GradingResult,
        current_plan: Dict[str, Any],
        attempt_number: int
    ) -> List[Tuple[CorrectionStrategy, Dict[str, Any]]]:
        """
        Generate correction strategies based on grading results.
        Returns list of (strategy, parameters) tuples.
        """
        corrections = []
        
        # Analyze issues and map to strategies
        for issue in grading.issues:
            issue_lower = issue.lower()
            
            if "no results" in issue_lower or "too few" in issue_lower:
                corrections.append((
                    CorrectionStrategy.EXPAND_SOURCES,
                    {"expand_to": "both", "increase_limit": True}
                ))
                corrections.append((
                    CorrectionStrategy.RELAX_FILTERS,
                    {"remove_filters": ["severity", "date_range"]}
                ))
            
            elif "not relevant" in issue_lower or "wrong topic" in issue_lower:
                corrections.append((
                    CorrectionStrategy.REFORMULATE_QUERY,
                    {"style": "clarify", "add_context": True}
                ))
            
            elif "too broad" in issue_lower or "too general" in issue_lower:
                corrections.append((
                    CorrectionStrategy.DECOMPOSE_QUERY,
                    {"max_subqueries": 3}
                ))
            
            elif "outdated" in issue_lower or "old data" in issue_lower:
                corrections.append((
                    CorrectionStrategy.TEMPORAL_ADJUSTMENT,
                    {"focus": "recent", "days": 90}
                ))
        
        # Add suggestions-based corrections
        for suggestion in grading.suggestions:
            suggestion_lower = suggestion.lower()
            
            if "synonym" in suggestion_lower or "alternative term" in suggestion_lower:
                corrections.append((
                    CorrectionStrategy.USE_SYNONYMS,
                    {"expand_terms": True}
                ))
            
            elif "context" in suggestion_lower or "background" in suggestion_lower:
                corrections.append((
                    CorrectionStrategy.CONTEXT_ENRICHMENT,
                    {"add_domain_context": True}
                ))
        
        # Prioritize corrections based on attempt number
        if attempt_number == 1:
            # First correction: try simple expansions
            priority = [CorrectionStrategy.EXPAND_SOURCES, CorrectionStrategy.RELAX_FILTERS]
        elif attempt_number == 2:
            # Second correction: try query reformulation
            priority = [CorrectionStrategy.REFORMULATE_QUERY, CorrectionStrategy.USE_SYNONYMS]
        else:
            # Third+ correction: try decomposition and context
            priority = [CorrectionStrategy.DECOMPOSE_QUERY, CorrectionStrategy.CONTEXT_ENRICHMENT]
        
        # Sort corrections by priority
        corrections.sort(key=lambda x: priority.index(x[0]) if x[0] in priority else 999)
        
        return corrections[:2]  # Return top 2 strategies
    
    async def reformulate_query(
        self,
        original_query: str,
        issues: List[str],
        context: Dict[str, Any] = None
    ) -> str:
        """
        Reformulate query to address identified issues.
        Uses DeepSeek R1 for intelligent reformulation.
        """
        reformulation_prompt = f"""<think>
The original query didn't return good results. I need to reformulate it to be more effective.
Issues found: {issues}
I should make it more specific for cybersecurity databases.
</think>

Reformulate this cybersecurity query to get better results:

Original Query: "{original_query}"
Issues Found: {json.dumps(issues)}
Context: {json.dumps(context or {}, default=str)}

Create a better query that:
1. Addresses the identified issues
2. Uses proper cybersecurity terminology
3. Is specific enough for database searches
4. Maintains the original intent

Respond with ONLY the reformulated query, no explanation.
"""
        
        try:
            reformulated = await llm_service.generate_response(
                reformulation_prompt,
                temperature=0.3,
                max_tokens=100
            )
            
            # Clean up response
            reformulated = reformulated.strip().strip('"').strip("'")
            
            # Ensure it's not empty or too similar
            if not reformulated or reformulated.lower() == original_query.lower():
                # Fallback to simple enhancement
                return f"{original_query} vulnerability exploit threat"
            
            logger.info(f"Query reformulated: '{original_query}' -> '{reformulated}'")
            return reformulated
            
        except Exception as e:
            logger.error(f"Query reformulation failed: {e}")
            return original_query
    
    async def decompose_complex_query(
        self,
        query: str,
        max_subqueries: int = 3
    ) -> List[str]:
        """
        Decompose complex query into simpler sub-queries.
        """
        decomposition_prompt = f"""<think>
This query might be too complex. I should break it down into simpler parts.
Each part should be a complete, searchable query.
</think>

Decompose this complex cybersecurity query into simpler sub-queries:

Query: "{query}"

Break it into {max_subqueries} simpler queries that together cover the original intent.
Each sub-query should be:
1. Self-contained and searchable
2. Focused on one aspect
3. Using proper cybersecurity terms

Respond in JSON format:
{{
    "subqueries": ["query1", "query2", "query3"]
}}
"""
        
        try:
            response = await llm_service.generate_response(
                decomposition_prompt,
                temperature=0.2,
                max_tokens=200
            )
            
            data = self._parse_json_response(response)
            subqueries = data.get("subqueries", [])
            
            if not subqueries:
                # Fallback: split by common conjunctions
                parts = query.replace(" and ", " | ").replace(" or ", " | ").split(" | ")
                subqueries = [p.strip() for p in parts if p.strip()][:max_subqueries]
            
            return subqueries
            
        except Exception as e:
            logger.error(f"Query decomposition failed: {e}")
            return [query]  # Return original as single query
    
    async def enrich_with_synonyms(
        self,
        query: str,
        domain: str = "cybersecurity"
    ) -> str:
        """
        Enrich query with domain-specific synonyms and related terms.
        """
        synonym_prompt = f"""Enhance this cybersecurity query with relevant synonyms and related terms:

Query: "{query}"

Add 2-3 highly relevant alternative terms or synonyms that would help find related information.
Focus on cybersecurity-specific terminology.

Respond with ONLY the enhanced query, no explanation.
Example: "ransomware" -> "ransomware malware cryptolocker encryption extortion"
"""
        
        try:
            enhanced = await llm_service.generate_response(
                synonym_prompt,
                temperature=0.2,
                max_tokens=100
            )
            
            return enhanced.strip()
            
        except Exception as e:
            logger.error(f"Synonym enrichment failed: {e}")
            return query
    
    def _prepare_results_summary(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Prepare a summary of results for analysis"""
        summary = []
        for i, result in enumerate(results[:5]):  # Analyze first 5 results
            if isinstance(result, dict):
                item = {
                    "index": i + 1,
                    "type": result.get("type", "unknown")
                }
                
                # Extract key fields based on result type
                if "cve_id" in result:
                    item["cve_id"] = result["cve_id"]
                    item["severity"] = result.get("severity", "unknown")
                    item["description"] = result.get("description", "")[:200]
                elif "content" in result:
                    item["content"] = result["content"][:200]
                    item["score"] = result.get("score", 0)
                elif "threat_actor" in result:
                    item["threat_actor"] = result["threat_actor"]
                    item["campaign"] = result.get("campaign", "")
                else:
                    item["summary"] = str(result)[:200]
                
                summary.append(item)
        
        return summary
    
    def _parse_json_response(self, response: str) -> Dict[str, Any]:
        """Parse JSON from LLM response, handling various formats"""
        try:
            # Try to extract JSON from response
            response = response.strip()
            
            # Find JSON block if wrapped in markdown
            if "```json" in response:
                start = response.find("```json") + 7
                end = response.find("```", start)
                response = response[start:end]
            elif "```" in response:
                start = response.find("```") + 3
                end = response.find("```", start)
                response = response[start:end]
            
            # Remove <think> tags if present
            if "<think>" in response:
                import re
                response = re.sub(r'<think>.*?</think>', '', response, flags=re.DOTALL)
            
            # Parse JSON
            return json.loads(response.strip())
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parsing failed: {e}")
            logger.debug(f"Response was: {response[:500]}")
            return {}
    
    def _simple_grade(self, results: List[Dict[str, Any]]) -> GradingResult:
        """Simple fallback grading based on result count and basic metrics"""
        result_count = len(results)
        
        if result_count == 0:
            relevance = 0.0
            completeness = 0.0
        elif result_count < 3:
            relevance = 0.4
            completeness = 0.3
        elif result_count < 10:
            relevance = 0.6
            completeness = 0.5
        else:
            relevance = 0.8
            completeness = 0.7
        
        issues = []
        suggestions = []
        
        if result_count == 0:
            issues.append("No results found")
            suggestions.append("Expand search criteria")
        elif result_count < 5:
            issues.append("Too few results")
            suggestions.append("Relax filters")
        
        return GradingResult(
            relevance_score=relevance,
            completeness_score=completeness,
            accuracy_confidence=0.5,
            issues=issues,
            suggestions=suggestions
        )


# Singleton instance
self_corrector = AdvancedSelfCorrector()