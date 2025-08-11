"""
Agent Coordinator for orchestrating multiple specialized cybersecurity agents.
Implements intelligent agent selection and result aggregation.
"""

import logging
from typing import Dict, Any, List, Optional
from enum import Enum
import asyncio
from datetime import datetime

from .base_agent import BaseAgent
from .threat_intelligence_agent import ThreatIntelligenceAgent
from .vulnerability_agent import VulnerabilityAgent
from ..routing import IntelligentRouteEngine, QueryIntent, QueryType

logger = logging.getLogger(__name__)


class AgentPriority(int, Enum):
    """Priority levels for agent selection."""
    PRIMARY = 1
    SECONDARY = 2
    FALLBACK = 3


class CoordinationStrategy(str, Enum):
    """Strategies for multi-agent coordination."""
    SINGLE_AGENT = "single_agent"
    PARALLEL = "parallel"
    SEQUENTIAL = "sequential"
    HIERARCHICAL = "hierarchical"


class AgentCoordinator:
    """
    Coordinates multiple cybersecurity agents for comprehensive analysis.
    Implements intelligent agent selection, orchestration, and result aggregation.
    """
    
    def __init__(self, route_engine: IntelligentRouteEngine):
        self.route_engine = route_engine
        self.agents: Dict[str, BaseAgent] = {}
        self.agent_priorities: Dict[QueryIntent, List[str]] = {}
        self.coordination_stats = {
            "total_coordinations": 0,
            "single_agent_executions": 0,
            "multi_agent_executions": 0,
            "successful_coordinations": 0,
            "average_response_time": 0.0
        }
        
        # Initialize agents
        self._initialize_agents()
        self._setup_agent_priorities()
    
    def _initialize_agents(self):
        """Initialize all specialized agents."""
        try:
            # Threat Intelligence Agent
            threat_agent = ThreatIntelligenceAgent(self.route_engine)
            threat_agent.initialize()
            self.agents["threat_intelligence"] = threat_agent
            
            # Vulnerability Analysis Agent
            vuln_agent = VulnerabilityAgent(self.route_engine)
            vuln_agent.initialize()
            self.agents["vulnerability"] = vuln_agent
            
            logger.info(f"Initialized {len(self.agents)} specialized agents")
            
        except Exception as e:
            logger.error(f"Failed to initialize agents: {str(e)}")
            raise
    
    def _setup_agent_priorities(self):
        """Setup agent priorities based on query intents."""
        self.agent_priorities = {
            QueryIntent.THREAT_ANALYSIS: ["threat_intelligence", "vulnerability"],
            QueryIntent.CVE_LOOKUP: ["vulnerability", "threat_intelligence"],
            QueryIntent.VULNERABILITY_SEARCH: ["vulnerability", "threat_intelligence"],
            QueryIntent.STATISTICS: ["vulnerability", "threat_intelligence"],
            QueryIntent.SIMILARITY_SEARCH: ["threat_intelligence", "vulnerability"],
            QueryIntent.EXPLANATION: ["threat_intelligence", "vulnerability"],
            QueryIntent.TREND_ANALYSIS: ["vulnerability", "threat_intelligence"]
        }
    
    async def coordinate_analysis(
        self, 
        query: str, 
        context: Optional[Dict[str, Any]] = None,
        strategy: CoordinationStrategy = CoordinationStrategy.SINGLE_AGENT
    ) -> Dict[str, Any]:
        """
        Coordinate analysis across multiple agents.
        
        Args:
            query: User query string
            context: Optional context for the query
            strategy: Coordination strategy to use
            
        Returns:
            Coordinated analysis results
        """
        start_time = datetime.utcnow()
        self.coordination_stats["total_coordinations"] += 1
        
        try:
            # Classify query to determine agent selection
            classification = self.route_engine.classifier.classify_query(query)
            
            # Select agents based on query intent and strategy
            selected_agents = self._select_agents(classification, strategy)
            
            # Execute coordination strategy
            if strategy == CoordinationStrategy.SINGLE_AGENT:
                result = await self._execute_single_agent(query, selected_agents[0], context)
                self.coordination_stats["single_agent_executions"] += 1
            
            elif strategy == CoordinationStrategy.PARALLEL:
                result = await self._execute_parallel(query, selected_agents, context)
                self.coordination_stats["multi_agent_executions"] += 1
            
            elif strategy == CoordinationStrategy.SEQUENTIAL:
                result = await self._execute_sequential(query, selected_agents, context)
                self.coordination_stats["multi_agent_executions"] += 1
            
            else:  # HIERARCHICAL
                result = await self._execute_hierarchical(query, selected_agents, context)
                self.coordination_stats["multi_agent_executions"] += 1
            
            # Calculate execution time
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Update statistics
            if result["success"]:
                self.coordination_stats["successful_coordinations"] += 1
            
            total_coords = self.coordination_stats["total_coordinations"]
            current_avg = self.coordination_stats["average_response_time"]
            self.coordination_stats["average_response_time"] = (
                (current_avg * (total_coords - 1) + execution_time) / total_coords
            )
            
            # Add coordination metadata
            result["coordination"] = {
                "strategy": strategy.value,
                "agents_used": selected_agents,
                "classification": {
                    "query_type": classification.query_type.value,
                    "intent": classification.intent.value,
                    "confidence": classification.confidence
                },
                "execution_time": execution_time
            }
            
            logger.info(f"Coordination completed: {strategy.value} with {len(selected_agents)} agents")
            return result
            
        except Exception as e:
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            logger.error(f"Coordination failed: {str(e)}")
            
            return {
                "success": False,
                "error": str(e),
                "results": [],
                "confidence": 0.0,
                "coordination": {
                    "strategy": strategy.value,
                    "agents_used": [],
                    "execution_time": execution_time
                }
            }
    
    def _select_agents(
        self, 
        classification, 
        strategy: CoordinationStrategy
    ) -> List[str]:
        """Select appropriate agents based on classification and strategy."""
        
        intent_agents = self.agent_priorities.get(classification.intent, ["vulnerability"])
        
        if strategy == CoordinationStrategy.SINGLE_AGENT:
            # Select the primary agent for this intent
            return [intent_agents[0]]
        
        elif strategy == CoordinationStrategy.PARALLEL:
            # Select top 2 agents for parallel execution
            return intent_agents[:2]
        
        elif strategy in [CoordinationStrategy.SEQUENTIAL, CoordinationStrategy.HIERARCHICAL]:
            # Use all relevant agents
            return intent_agents
        
        else:
            return [intent_agents[0]]
    
    async def _execute_single_agent(
        self, 
        query: str, 
        agent_name: str, 
        context: Optional[Dict]
    ) -> Dict[str, Any]:
        """Execute analysis with a single agent."""
        
        if agent_name not in self.agents:
            raise ValueError(f"Agent {agent_name} not available")
        
        agent = self.agents[agent_name]
        result = await agent.execute(query, context)
        
        return {
            "success": result["success"],
            "results": result["results"],
            "confidence": result["confidence"],
            "agent_responses": {agent_name: result},
            "error": result.get("error")
        }
    
    async def _execute_parallel(
        self, 
        query: str, 
        agent_names: List[str], 
        context: Optional[Dict]
    ) -> Dict[str, Any]:
        """Execute analysis with multiple agents in parallel."""
        
        # Create tasks for all agents
        tasks = []
        for agent_name in agent_names:
            if agent_name in self.agents:
                agent = self.agents[agent_name]
                tasks.append(agent.execute(query, context))
        
        if not tasks:
            raise ValueError("No valid agents selected for parallel execution")
        
        # Execute all tasks concurrently
        agent_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Process results
        successful_results = []
        agent_responses = {}
        total_confidence = 0.0
        successful_agents = 0
        
        for i, result in enumerate(agent_results):
            agent_name = agent_names[i] if i < len(agent_names) else f"agent_{i}"
            
            if isinstance(result, Exception):
                agent_responses[agent_name] = {
                    "success": False,
                    "error": str(result),
                    "results": [],
                    "confidence": 0.0
                }
            else:
                agent_responses[agent_name] = result
                if result["success"]:
                    successful_results.extend(result["results"])
                    total_confidence += result["confidence"]
                    successful_agents += 1
        
        # Calculate aggregate confidence
        aggregate_confidence = total_confidence / successful_agents if successful_agents > 0 else 0.0
        
        # Merge and deduplicate results
        merged_results = self._merge_results(successful_results)
        
        return {
            "success": successful_agents > 0,
            "results": merged_results,
            "confidence": aggregate_confidence,
            "agent_responses": agent_responses,
            "error": None if successful_agents > 0 else "All agents failed"
        }
    
    async def _execute_sequential(
        self, 
        query: str, 
        agent_names: List[str], 
        context: Optional[Dict]
    ) -> Dict[str, Any]:
        """Execute analysis with agents sequentially, passing context forward."""
        
        all_results = []
        agent_responses = {}
        cumulative_confidence = 0.0
        successful_agents = 0
        enriched_context = context or {}
        
        for agent_name in agent_names:
            if agent_name not in self.agents:
                continue
                
            agent = self.agents[agent_name]
            
            # Execute agent with enriched context
            result = await agent.execute(query, enriched_context)
            agent_responses[agent_name] = result
            
            if result["success"]:
                all_results.extend(result["results"])
                cumulative_confidence += result["confidence"]
                successful_agents += 1
                
                # Enrich context for next agent
                enriched_context[f"{agent_name}_results"] = result["results"][:5]  # Top 5 results
                enriched_context[f"{agent_name}_confidence"] = result["confidence"]
        
        # Calculate final confidence
        final_confidence = cumulative_confidence / successful_agents if successful_agents > 0 else 0.0
        
        return {
            "success": successful_agents > 0,
            "results": all_results,
            "confidence": final_confidence,
            "agent_responses": agent_responses,
            "error": None if successful_agents > 0 else "All agents failed"
        }
    
    async def _execute_hierarchical(
        self, 
        query: str, 
        agent_names: List[str], 
        context: Optional[Dict]
    ) -> Dict[str, Any]:
        """Execute analysis hierarchically with primary-secondary-fallback logic."""
        
        agent_responses = {}
        
        for i, agent_name in enumerate(agent_names):
            if agent_name not in self.agents:
                continue
            
            agent = self.agents[agent_name]
            result = await agent.execute(query, context)
            agent_responses[agent_name] = result
            
            # If primary agent succeeds with high confidence, use its results
            if i == 0 and result["success"] and result["confidence"] >= 0.7:
                return {
                    "success": True,
                    "results": result["results"],
                    "confidence": result["confidence"],
                    "agent_responses": agent_responses,
                    "primary_agent": agent_name,
                    "error": None
                }
            
            # If secondary agent provides better results, combine with primary
            elif i == 1 and result["success"]:
                primary_results = agent_responses.get(agent_names[0], {}).get("results", [])
                secondary_results = result["results"]
                
                # Merge results with secondary taking priority for higher confidence
                if result["confidence"] > agent_responses.get(agent_names[0], {}).get("confidence", 0.0):
                    merged_results = secondary_results + primary_results
                    confidence = result["confidence"]
                else:
                    merged_results = primary_results + secondary_results
                    confidence = agent_responses.get(agent_names[0], {}).get("confidence", 0.0)
                
                return {
                    "success": True,
                    "results": self._merge_results(merged_results),
                    "confidence": confidence,
                    "agent_responses": agent_responses,
                    "primary_agent": agent_names[0],
                    "secondary_agent": agent_name,
                    "error": None
                }
        
        # If we reach here, try to salvage any partial results
        all_results = []
        max_confidence = 0.0
        
        for agent_name, response in agent_responses.items():
            if response.get("success") and response.get("results"):
                all_results.extend(response["results"])
                max_confidence = max(max_confidence, response.get("confidence", 0.0))
        
        return {
            "success": len(all_results) > 0,
            "results": self._merge_results(all_results),
            "confidence": max_confidence,
            "agent_responses": agent_responses,
            "error": "Hierarchical fallback results" if all_results else "All agents failed"
        }
    
    def _merge_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Merge and deduplicate results from multiple agents.
        Prioritizes higher confidence and more recent results.
        """
        if not results:
            return []
        
        # Group by result type and content similarity
        merged = {}
        
        for result in results:
            result_type = result.get("type", "unknown")
            content_key = str(result.get("cve_id", result.get("id", result.get("title", ""))))[:100]
            
            key = f"{result_type}_{hash(content_key) % 10000}"
            
            if key not in merged:
                merged[key] = result
            else:
                # Keep result with higher confidence or more recent timestamp
                existing = merged[key]
                current_conf = result.get("confidence", 0.0)
                existing_conf = existing.get("confidence", 0.0)
                
                if current_conf > existing_conf:
                    merged[key] = result
        
        # Sort by confidence and return top results
        final_results = list(merged.values())
        final_results.sort(key=lambda x: x.get("confidence", 0.0), reverse=True)
        
        return final_results[:50]  # Limit to top 50 results
    
    def get_agent_status(self) -> Dict[str, Any]:
        """Get status and statistics for all agents."""
        status = {
            "total_agents": len(self.agents),
            "agent_details": {},
            "coordination_stats": self.coordination_stats
        }
        
        for agent_name, agent in self.agents.items():
            status["agent_details"][agent_name] = {
                "name": agent.name,
                "description": agent.description,
                "execution_stats": agent.get_execution_stats(),
                "initialized": agent.graph is not None
            }
        
        return status
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on all agents."""
        health_status = {
            "coordinator_healthy": True,
            "agents": {},
            "overall_status": "healthy"
        }
        
        for agent_name, agent in self.agents.items():
            try:
                # Simple health check - verify agent is initialized
                is_healthy = agent.graph is not None
                health_status["agents"][agent_name] = {
                    "healthy": is_healthy,
                    "initialized": is_healthy,
                    "error": None
                }
            except Exception as e:
                health_status["agents"][agent_name] = {
                    "healthy": False,
                    "initialized": False,
                    "error": str(e)
                }
                health_status["overall_status"] = "degraded"
        
        # Check if any agents are unhealthy
        unhealthy_agents = [
            name for name, status in health_status["agents"].items() 
            if not status["healthy"]
        ]
        
        if unhealthy_agents:
            if len(unhealthy_agents) == len(self.agents):
                health_status["overall_status"] = "critical"
            else:
                health_status["overall_status"] = "degraded"
        
        return health_status