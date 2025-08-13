import asyncio
import time
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
import logging
import json

from src.routing.query_classifier import query_classifier, QueryType, DataSource
from src.routing.self_correction import self_corrector, CorrectionStrategy, GradingResult
from src.routing.relevance_scorer import relevance_scorer, RelevanceMetrics
from src.database.connection import db_manager
from src.database.postgresql_adapter import PostgreSQLAdapter
from src.vector_store.qdrant_adapter import qdrant_adapter, SearchResult
from src.utils.llm_service import llm_service

logger = logging.getLogger(__name__)


@dataclass
class QueryResult:
    """Result from query execution"""
    data: List[Dict[str, Any]]
    source: str
    relevance: float
    response_time_ms: int
    metadata: Dict[str, Any]


class SelfCorrectingRouteEngine:
    """
    Intelligent routing engine with self-correction capabilities
    Routes queries to optimal data sources and validates results
    """
    
    def __init__(self):
        self.relevance_threshold = 0.7
        self.min_results_threshold = 3
        self.max_retries = 3
        self.correction_attempts = 0
        self.self_corrector = self_corrector
    
    async def route_and_execute(
        self,
        query: str,
        mode: str = "balanced"  # fast, balanced, comprehensive
    ) -> Dict[str, Any]:
        """
        Main entry point for query routing and execution
        """
        start_time = time.time()
        
        # Generate routing plan
        routing_plan = query_classifier.generate_routing_plan(query)
        logger.info(f"Routing plan: {routing_plan}")
        
        # Check cache first
        cached_result = await self._check_cache(routing_plan["cache_key"])
        if cached_result and mode != "comprehensive":
            return cached_result
        
        # Execute based on data source
        results = await self._execute_query(query, routing_plan, mode)
        
        # Grade relevance
        relevance_score, relevance_metrics = await self._grade_relevance(query, results)
        
        # Self-correct if needed
        self.correction_attempts = 0
        while relevance_score < self.relevance_threshold and self.correction_attempts < self.max_retries:
            logger.info(f"Low relevance score: {relevance_score:.2f}. Attempting self-correction (attempt {self.correction_attempts + 1})")
            logger.info(f"Explanation: {relevance_metrics.score_explanation}")
            
            # Convert relevance metrics to grading for self-correction
            grading = GradingResult(
                relevance_score=relevance_metrics.relevance_score,
                completeness_score=relevance_metrics.result_diversity,
                accuracy_confidence=relevance_metrics.source_reliability,
                issues=relevance_metrics.limitations,
                suggestions=["Expand search", "Try different keywords"]
            )
            
            results = await self._self_correct(query, routing_plan, results, grading)
            relevance_score, relevance_metrics = await self._grade_relevance(query, results)
            self.correction_attempts += 1
        
        # Generate final response
        response = await self._generate_response(
            query=query,
            results=results,
            routing_plan=routing_plan,
            relevance_metrics=relevance_metrics,
            response_time_ms=int((time.time() - start_time) * 1000)
        )
        
        # Cache successful results
        if relevance_score >= self.relevance_threshold:
            await self._cache_result(routing_plan["cache_key"], response)
        
        # Log query performance
        await self._log_query_performance(
            query=query,
            routing_plan=routing_plan,
            response=response,
            relevance_metrics=relevance_metrics
        )
        
        return response
    
    async def _execute_query(
        self,
        query: str,
        routing_plan: Dict[str, Any],
        mode: str
    ) -> List[QueryResult]:
        """Execute query based on routing plan"""
        results = []
        data_source = DataSource(routing_plan["data_source"])
        
        if data_source in [DataSource.POSTGRESQL, DataSource.BOTH]:
            pg_result = await self._execute_postgresql_query(
                query=query,
                filters=routing_plan["filters"],
                params=routing_plan.get("sql_params", {}),
                mode=mode
            )
            if pg_result:
                results.append(pg_result)
        
        if data_source in [DataSource.QDRANT, DataSource.BOTH]:
            vector_result = await self._execute_vector_query(
                query=query,
                filters=routing_plan["filters"],
                params=routing_plan.get("vector_params", {}),
                mode=mode
            )
            if vector_result:
                results.append(vector_result)
        
        # Apply deduplication to prevent duplicate CVEs from multiple sources
        logger.info(f"Before deduplication: {len(results)} result groups with {sum(len(r.data) for r in results)} total items")
        deduplicated_results = self._deduplicate_results(results)
        logger.info(f"After deduplication: {len(deduplicated_results)} result groups")
        return deduplicated_results
    
    async def _execute_postgresql_query(
        self,
        query: str,
        filters: Dict[str, Any],
        params: Dict[str, Any],
        mode: str
    ) -> Optional[QueryResult]:
        """Execute PostgreSQL query"""
        try:
            start_time = time.time()
            
            async with db_manager.get_postgres_session() as session:
                adapter = PostgreSQLAdapter(session)
                
                # Determine query type and execute
                if filters.get("cve_id"):
                    # Specific CVE lookup
                    data = await adapter.search_cves(
                        query=filters["cve_id"],
                        limit=1
                    )
                elif "severity" in filters:
                    # Severity-based search
                    data = await adapter.search_cves(
                        query=query,
                        severity=filters["severity"],
                        limit=params.get("limit", 50)
                    )
                elif "threat_actor" in query.lower():
                    # Threat actor search
                    data = await adapter.search_threat_actors(
                        query=query,
                        active_only=True,
                        limit=params.get("limit", 50)
                    )
                elif "mitre" in query.lower() or "technique" in query.lower():
                    # MITRE technique search
                    data = await adapter.search_mitre_techniques(
                        query=query,
                        limit=params.get("limit", 50)
                    )
                elif "malware" in query.lower():
                    # Malware search
                    data = await adapter.search_malware(
                        query=query,
                        limit=params.get("limit", 50)
                    )
                elif "ioc" in query.lower() or filters.get("ip_addresses"):
                    # IOC search
                    data = await adapter.search_iocs(
                        query=query,
                        active_only=True,
                        limit=params.get("limit", 100)
                    )
                elif "landscape" in query.lower() or "summary" in query.lower():
                    # Threat landscape summary
                    days_back = int(filters.get("days", params.get("days_back", 30)))
                    data = [await adapter.get_threat_landscape_summary(days_back)]
                else:
                    # General search
                    data = await adapter.search_cves(
                        query=query,
                        limit=params.get("limit", 50)
                    )
            
            response_time = int((time.time() - start_time) * 1000)
            
            return QueryResult(
                data=data,
                source="postgresql",
                relevance=0.9 if data else 0.3,
                response_time_ms=response_time,
                metadata={
                    "query_type": "structured",
                    "result_count": len(data),
                    "filters_applied": filters
                }
            )
            
        except Exception as e:
            logger.error(f"PostgreSQL query failed: {e}")
            return None
    
    async def _execute_vector_query(
        self,
        query: str,
        filters: Dict[str, Any],
        params: Dict[str, Any],
        mode: str
    ) -> Optional[QueryResult]:
        """Execute vector database query"""
        try:
            start_time = time.time()
            
            # Build filter conditions for Qdrant
            filter_conditions = {}
            if filters.get("doc_type"):
                filter_conditions["type"] = filters["doc_type"]
            if filters.get("source"):
                filter_conditions["source"] = filters["source"]
            
            # Execute search
            search_results = await qdrant_adapter.search_documents(
                query=query,
                limit=params.get("limit", 10),
                score_threshold=params.get("score_threshold", 0.5),
                filter_conditions=filter_conditions if filter_conditions else None
            )
            
            # Convert to standard format
            data = []
            for result in search_results:
                data.append({
                    "content": result.content,
                    "metadata": result.metadata,
                    "score": result.score,
                    "id": result.id
                })
            
            response_time = int((time.time() - start_time) * 1000)
            
            return QueryResult(
                data=data,
                source="qdrant",
                relevance=max([r.score for r in search_results]) if search_results else 0.3,
                response_time_ms=response_time,
                metadata={
                    "query_type": "semantic",
                    "result_count": len(data),
                    "avg_score": sum(r.score for r in search_results) / len(search_results) if search_results else 0
                }
            )
            
        except Exception as e:
            logger.error(f"Vector query failed: {e}")
            return None
    
    async def _grade_relevance(
        self,
        query: str,
        results: List[QueryResult]
    ) -> Tuple[float, RelevanceMetrics]:
        """Grade the relevance of results using improved relevance scoring"""
        if not results or not any(r.data for r in results):
            return 0.0, relevance_scorer._no_results_metrics()
        
        # Combine all results for scoring
        all_data = []
        sources_used = []
        
        for r in results:
            all_data.extend(r.data)
            sources_used.append(r.source)
        
        # Use improved relevance scoring
        relevance_metrics = relevance_scorer.calculate_relevance(
            query=query,
            results=all_data,
            sources_used=sources_used,
            query_metadata=None
        )
        
        return relevance_metrics.overall_score, relevance_metrics
    
    
    async def _self_correct(
        self,
        query: str,
        routing_plan: Dict[str, Any],
        initial_results: List[QueryResult],
        grading: GradingResult
    ) -> List[QueryResult]:
        """Attempt to self-correct poor results using advanced strategies"""
        
        # Generate correction strategies
        correction_strategies = await self.self_corrector.generate_corrections(
            query=query,
            grading=grading,
            current_plan=routing_plan,
            attempt_number=self.correction_attempts + 1
        )
        
        corrected_results = initial_results
        
        for strategy, params in correction_strategies:
            logger.info(f"Applying correction strategy: {strategy.value}")
            
            if strategy == CorrectionStrategy.EXPAND_SOURCES:
                # Expand to both databases
                expanded_plan = routing_plan.copy()
                expanded_plan["data_source"] = "both"
                if params.get("increase_limit"):
                    expanded_plan["sql_params"] = {"limit": 100}
                    expanded_plan["vector_params"] = {"limit": 20}
                corrected_results = await self._execute_query(query, expanded_plan, "comprehensive")
            
            elif strategy == CorrectionStrategy.RELAX_FILTERS:
                # Remove specified filters
                relaxed_plan = routing_plan.copy()
                filters_to_remove = params.get("remove_filters", [])
                for filter_key in filters_to_remove:
                    relaxed_plan["filters"].pop(filter_key, None)
                corrected_results = await self._execute_query(query, relaxed_plan, "comprehensive")
            
            elif strategy == CorrectionStrategy.REFORMULATE_QUERY:
                # Reformulate the query
                reformulated = await self.self_corrector.reformulate_query(
                    original_query=query,
                    issues=grading.issues,
                    context=routing_plan
                )
                new_plan = query_classifier.generate_routing_plan(reformulated)
                corrected_results = await self._execute_query(reformulated, new_plan, "comprehensive")
            
            elif strategy == CorrectionStrategy.DECOMPOSE_QUERY:
                # Decompose into sub-queries
                subqueries = await self.self_corrector.decompose_complex_query(
                    query=query,
                    max_subqueries=params.get("max_subqueries", 3)
                )
                all_results = []
                for subquery in subqueries:
                    sub_plan = query_classifier.generate_routing_plan(subquery)
                    sub_results = await self._execute_query(subquery, sub_plan, "balanced")
                    all_results.extend(sub_results)
                corrected_results = all_results
            
            elif strategy == CorrectionStrategy.USE_SYNONYMS:
                # Enrich with synonyms
                enriched_query = await self.self_corrector.enrich_with_synonyms(query)
                new_plan = query_classifier.generate_routing_plan(enriched_query)
                corrected_results = await self._execute_query(enriched_query, new_plan, "comprehensive")
            
            elif strategy == CorrectionStrategy.TEMPORAL_ADJUSTMENT:
                # Add temporal filters
                temporal_plan = routing_plan.copy()
                temporal_plan["filters"]["days_back"] = params.get("days", 90)
                corrected_results = await self._execute_query(query, temporal_plan, "comprehensive")
            
            # Check if correction improved results
            if corrected_results and len(corrected_results) > 0:
                if any(r.data for r in corrected_results):
                    logger.info(f"Correction strategy {strategy.value} produced results")
                    break
        
        return corrected_results if corrected_results else initial_results
    
    async def _generate_response(
        self,
        query: str,
        results: List[QueryResult],
        routing_plan: Dict[str, Any],
        relevance_metrics: RelevanceMetrics,
        response_time_ms: int
    ) -> Dict[str, Any]:
        """Generate final response"""
        # Combine all results
        all_data = []
        sources_used = []
        
        for result in results:
            all_data.extend(result.data)
            sources_used.append(result.source)
        
        # Generate natural language summary if needed
        summary = None
        if all_data and routing_plan.get("requires_llm", False):
            summary = await self._generate_summary(query, all_data)
        
        return {
            "query": query,
            "results": all_data[:50],  # Limit to 50 results
            "summary": summary,
            "metadata": {
                "query_type": routing_plan["query_type"],
                "sources_used": sources_used,
                "relevance_score": relevance_metrics.overall_score,
                "response_time_ms": response_time_ms,
                "result_count": len(all_data),
                "self_corrected": relevance_metrics.overall_score < self.relevance_threshold,
                "cache_hit": False
            },
            "relevance_metrics": relevance_metrics.to_dict()
        }
    
    async def _generate_summary(
        self,
        query: str,
        data: List[Dict[str, Any]]
    ) -> str:
        """Generate natural language summary of results"""
        try:
            # Prepare data summary
            data_summary = json.dumps(data[:5], indent=2, default=str)[:2000]
            
            prompt = f"""Based on the following threat intelligence data, provide a concise summary that answers the user's query.
            
            User Query: "{query}"
            
            Data:
            {data_summary}
            
            Provide a clear, technical summary in 2-3 sentences that directly addresses the query.
            Focus on the most important findings and actionable insights.
            """
            
            summary = await llm_service.generate_response(
                prompt,
                temperature=0.3,
                max_tokens=200
            )
            
            return summary.strip()
            
        except Exception as e:
            logger.error(f"Summary generation failed: {e}")
            return None
    
    async def _check_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Check cache for results"""
        try:
            redis_client = await db_manager.get_redis_client()
            cached = await redis_client.get(f"query_cache:{cache_key}")
            
            if cached:
                logger.info(f"Cache hit for key: {cache_key}")
                result = json.loads(cached)
                result["metadata"]["cache_hit"] = True
                return result
                
        except Exception as e:
            logger.error(f"Cache check failed: {e}")
        
        return None
    
    async def _cache_result(
        self,
        cache_key: str,
        result: Dict[str, Any]
    ) -> None:
        """Cache successful results"""
        try:
            redis_client = await db_manager.get_redis_client()
            await redis_client.setex(
                f"query_cache:{cache_key}",
                3600,  # 1 hour TTL
                json.dumps(result, default=str)
            )
            logger.info(f"Cached result for key: {cache_key}")
            
        except Exception as e:
            logger.error(f"Cache write failed: {e}")
    
    def _deduplicate_results(self, results: List[QueryResult]) -> List[QueryResult]:
        """
        Remove duplicate CVEs and threat intelligence items from multiple sources.
        Keeps the highest relevance version of each duplicate.
        """
        if not results:
            return results
        
        # Combine all data from all result sources
        all_items = []
        for result in results:
            for item in result.data:
                # Add source information to each item
                item_with_source = item.copy()
                item_with_source['_source_db'] = result.source
                item_with_source['_relevance'] = result.relevance
                all_items.append(item_with_source)
        
        # Track duplicates by CVE ID and content hash
        seen_cve_ids = {}
        seen_content_hashes = {}
        deduplicated_items = []
        
        for item in all_items:
            # Extract unique identifiers
            cve_id = self._extract_cve_id(item)
            content_hash = self._get_content_hash(item)
            
            logger.info(f"Dedup: Processing item with CVE ID: {cve_id}, content hash: {content_hash[:8] if content_hash else None}")
            
            is_duplicate = False
            
            # Check for CVE ID duplicates first
            if cve_id and cve_id in seen_cve_ids:
                # Keep the one with higher relevance
                existing_item = seen_cve_ids[cve_id]
                if item['_relevance'] > existing_item['_relevance']:
                    # Replace with higher relevance version
                    deduplicated_items.remove(existing_item)
                    seen_cve_ids[cve_id] = item
                    deduplicated_items.append(item)
                    logger.info(f"Replaced duplicate CVE {cve_id} with higher relevance version")
                else:
                    logger.info(f"Skipped duplicate CVE {cve_id} with lower relevance")
                is_duplicate = True
            
            # Check for content duplicates (for all items, including CVEs with same content)
            elif content_hash and content_hash in seen_content_hashes:
                existing_item = seen_content_hashes[content_hash]
                if item['_relevance'] > existing_item['_relevance']:
                    deduplicated_items.remove(existing_item)
                    seen_content_hashes[content_hash] = item
                    deduplicated_items.append(item)
                    logger.info(f"Replaced duplicate content with higher relevance version")
                else:
                    logger.info(f"Skipped duplicate content with lower relevance")
                is_duplicate = True
            else:
                # Track both CVE ID and content hash for new items
                if cve_id:
                    seen_cve_ids[cve_id] = item
                if content_hash:
                    seen_content_hashes[content_hash] = item
            
            # Add if not a duplicate
            if not is_duplicate:
                deduplicated_items.append(item)
        
        # Create new QueryResult with deduplicated data
        if deduplicated_items:
            # Calculate metrics for deduplicated results
            total_relevance = sum(item['_relevance'] for item in deduplicated_items)
            avg_relevance = total_relevance / len(deduplicated_items)
            
            # Clean up internal fields
            clean_items = []
            for item in deduplicated_items:
                clean_item = item.copy()
                clean_item.pop('_source_db', None)
                clean_item.pop('_relevance', None)
                clean_items.append(clean_item)
            
            # Return single consolidated result
            consolidated_result = QueryResult(
                data=clean_items,
                source="hybrid",
                relevance=avg_relevance,
                response_time_ms=0,  # Will be calculated at higher level
                metadata={
                    "deduplicated": True,
                    "original_count": len(all_items),
                    "deduplicated_count": len(clean_items),
                    "sources_combined": [r.source for r in results]
                }
            )
            
            logger.info(f"Deduplication: {len(all_items)} → {len(clean_items)} items")
            return [consolidated_result]
        
        return results
    
    def _extract_cve_id(self, item: Dict[str, Any]) -> Optional[str]:
        """Extract CVE ID from various item formats"""
        # Direct CVE ID field
        if 'cve_id' in item:
            return item['cve_id']
        
        # Metadata CVE ID (from Qdrant)
        if 'metadata' in item and isinstance(item['metadata'], dict):
            return item['metadata'].get('cve_id')
        
        # Extract from content field
        content = item.get('content', '')
        if isinstance(content, str) and 'CVE-' in content:
            import re
            match = re.search(r'CVE-\d{4}-\d+', content)
            if match:
                return match.group(0)
        
        return None
    
    def _get_content_hash(self, item: Dict[str, Any]) -> Optional[str]:
        """Generate hash for content-based deduplication"""
        import hashlib
        
        # Use content field if available
        content = item.get('content', '')
        if isinstance(content, str) and len(content) > 50:
            # Use a larger sample (400 chars) to better catch duplicates
            # and normalize whitespace for consistent hashing
            content_sample = ' '.join(content[:400].split())
            return hashlib.md5(content_sample.encode()).hexdigest()
        
        # Fallback to description
        description = item.get('description', '')
        if isinstance(description, str) and len(description) > 50:
            desc_sample = ' '.join(description[:400].split())
            return hashlib.md5(desc_sample.encode()).hexdigest()
        
        return None

    async def _log_query_performance(
        self,
        query: str,
        routing_plan: Dict[str, Any],
        response: Dict[str, Any],
        relevance_metrics: RelevanceMetrics
    ) -> None:
        """Log query performance metrics"""
        try:
            async with db_manager.get_postgres_session() as session:
                adapter = PostgreSQLAdapter(session)
                
                await adapter.log_query(
                    query_text=query,
                    query_type=routing_plan["query_type"],
                    route_taken=routing_plan["data_source"],
                    response_time_ms=response["metadata"]["response_time_ms"],
                    result_count=response["metadata"]["result_count"],
                    confidence_score=relevance_metrics.overall_score,
                    self_correction_triggered=response["metadata"]["self_corrected"]
                )
                
        except Exception as e:
            logger.error(f"Query logging failed: {e}")


# Global route engine instance
route_engine = SelfCorrectingRouteEngine()