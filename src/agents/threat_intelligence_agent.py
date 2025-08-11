"""
Threat Intelligence Agent for autonomous cybersecurity analysis.
Specializes in threat actor analysis, campaign tracking, and intelligence correlation.
"""

import logging
from typing import Dict, Any, List
import json

from langchain.schema import HumanMessage, AIMessage
from langchain.tools import Tool
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolExecutor

from .base_agent import BaseAgent, AgentState
from ..routing import IntelligentRouteEngine
from config.settings import settings

logger = logging.getLogger(__name__)


class ThreatIntelligenceAgent(BaseAgent):
    """
    Specialized agent for threat intelligence analysis and correlation.
    Focuses on APT groups, campaigns, TTPs, and threat landscape analysis.
    """
    
    def __init__(self, route_engine: IntelligentRouteEngine):
        super().__init__(
            name="ThreatIntelligenceAgent",
            description="Expert in threat actor analysis, campaign tracking, and strategic intelligence"
        )
        self.route_engine = route_engine
        self.tools = self._initialize_tools()
        self.tool_executor = ToolExecutor(self.tools)
        
    def _initialize_tools(self) -> List[Tool]:
        """Initialize specialized tools for threat intelligence analysis."""
        return [
            Tool(
                name="search_threat_actors",
                description="Search for information about specific threat actors or APT groups. Input should be actor name or characteristics.",
                func=self._search_threat_actors
            ),
            Tool(
                name="analyze_campaign",
                description="Analyze threat campaign details including TTPs, infrastructure, and attribution. Input should be campaign name or characteristics.",
                func=self._analyze_campaign
            ),
            Tool(
                name="correlate_threats",
                description="Correlate threats across multiple sources to identify patterns and connections. Input should be correlation parameters.",
                func=self._correlate_threats
            ),
            Tool(
                name="assess_threat_landscape",
                description="Assess current threat landscape and emerging threats. Input should be time frame or specific sectors.",
                func=self._assess_threat_landscape
            ),
            Tool(
                name="extract_iocs",
                description="Extract and validate Indicators of Compromise from threat intelligence. Input should be threat data or report content.",
                func=self._extract_iocs
            )
        ]
    
    def create_graph(self) -> StateGraph:
        """Create the threat intelligence analysis workflow graph."""
        graph = StateGraph(AgentState)
        
        # Define nodes
        graph.add_node("analyze_query", self._analyze_query)
        graph.add_node("gather_intelligence", self._gather_intelligence)
        graph.add_node("correlate_data", self._correlate_data)
        graph.add_node("assess_threats", self._assess_threats)
        graph.add_node("generate_analysis", self._generate_analysis)
        graph.add_node("validate_results", self.validate_results)
        graph.add_node("handle_error", self._handle_agent_error)
        
        # Define edges
        graph.set_entry_point("analyze_query")
        
        graph.add_conditional_edges(
            "analyze_query",
            self._should_continue,
            {
                "gather_intelligence": "gather_intelligence",
                "error": "handle_error",
                "end": END
            }
        )
        
        graph.add_edge("gather_intelligence", "correlate_data")
        graph.add_edge("correlate_data", "assess_threats")
        graph.add_edge("assess_threats", "generate_analysis")
        graph.add_edge("generate_analysis", "validate_results")
        
        graph.add_conditional_edges(
            "validate_results",
            self._should_retry,
            {
                "retry": "gather_intelligence",
                "end": END,
                "error": "handle_error"
            }
        )
        
        graph.add_edge("handle_error", END)
        
        return graph
    
    async def _analyze_query(self, state: AgentState) -> AgentState:
        """Analyze the query to determine threat intelligence requirements."""
        query = state["query"]
        
        # Create analysis prompt
        prompt = self.create_prompt_template("""
        Analyze this cybersecurity query to determine the threat intelligence approach:
        
        Query: {query}
        
        Determine:
        1. Primary threat intelligence focus (actor, campaign, TTP, landscape)
        2. Required data sources (internal, external, OSINT)
        3. Analysis depth (tactical, operational, strategic)
        4. Key entities to investigate (actors, malware, infrastructure)
        5. Expected output format (brief, detailed, actionable recommendations)
        
        Respond with a structured analysis plan in JSON format.
        """)
        
        try:
            response = await self.llm.ainvoke(prompt.format_messages(query=query))
            
            # Parse the analysis plan
            analysis_plan = self._parse_llm_response(response.content)
            
            state["metadata"]["analysis_plan"] = analysis_plan
            state["context"]["intelligence_focus"] = analysis_plan.get("primary_focus", "general")
            state["context"]["analysis_depth"] = analysis_plan.get("analysis_depth", "operational")
            
            logger.info(f"Query analysis completed: {analysis_plan.get('primary_focus', 'unknown')}")
            
        except Exception as e:
            state = await self.handle_error(state, e)
        
        return state
    
    async def _gather_intelligence(self, state: AgentState) -> AgentState:
        """Gather threat intelligence from multiple sources."""
        query = state["query"]
        intelligence_focus = state["context"].get("intelligence_focus", "general")
        
        try:
            # Use routing engine to gather initial data
            route_result = await self.route_engine.route_query(query, state["context"])
            
            intelligence_data = {
                "primary_data": route_result.data,
                "source": route_result.source,
                "confidence": route_result.confidence_score
            }
            
            # Enhance with specialized intelligence gathering based on focus
            if intelligence_focus == "actor":
                enhanced_data = await self._search_threat_actors(query)
                intelligence_data["actor_intelligence"] = enhanced_data
                
            elif intelligence_focus == "campaign":
                enhanced_data = await self._analyze_campaign(query)
                intelligence_data["campaign_intelligence"] = enhanced_data
                
            elif intelligence_focus == "landscape":
                enhanced_data = await self._assess_threat_landscape(query)
                intelligence_data["landscape_analysis"] = enhanced_data
            
            state["context"]["intelligence_data"] = intelligence_data
            logger.info(f"Intelligence gathering completed: {len(route_result.data)} primary records")
            
        except Exception as e:
            state = await self.handle_error(state, e)
        
        return state
    
    async def _correlate_data(self, state: AgentState) -> AgentState:
        """Correlate intelligence data to identify patterns and connections."""
        intelligence_data = state["context"].get("intelligence_data", {})
        
        try:
            correlation_prompt = self.create_prompt_template("""
            Correlate this threat intelligence data to identify patterns, connections, and insights:
            
            Primary Data: {primary_data}
            
            Enhanced Intelligence: {enhanced_data}
            
            Focus on:
            1. Actor-to-campaign relationships
            2. TTP overlaps and evolution
            3. Infrastructure connections
            4. Timeline correlations
            5. Victim targeting patterns
            
            Provide correlation findings in structured format with confidence levels.
            """)
            
            primary_data = json.dumps(intelligence_data.get("primary_data", [])[:5], default=str)
            enhanced_data = json.dumps(
                {k: v for k, v in intelligence_data.items() if k != "primary_data"}, 
                default=str
            )
            
            response = await self.llm.ainvoke(
                correlation_prompt.format_messages(
                    primary_data=primary_data,
                    enhanced_data=enhanced_data
                )
            )
            
            correlations = self._parse_llm_response(response.content)
            state["context"]["correlations"] = correlations
            
            logger.info("Data correlation completed")
            
        except Exception as e:
            state = await self.handle_error(state, e)
        
        return state
    
    async def _assess_threats(self, state: AgentState) -> AgentState:
        """Assess threat levels and implications."""
        correlations = state["context"].get("correlations", {})
        intelligence_data = state["context"].get("intelligence_data", {})
        
        try:
            assessment_prompt = self.create_prompt_template("""
            Assess the threat implications based on this intelligence:
            
            Correlations: {correlations}
            
            Intelligence Summary: {intelligence_summary}
            
            Provide threat assessment including:
            1. Threat level (Critical/High/Medium/Low)
            2. Affected sectors/regions
            3. Attack likelihood and timeline
            4. Potential impact assessment
            5. Recommended defensive actions
            6. Intelligence gaps and collection requirements
            
            Format as structured threat assessment.
            """)
            
            correlations_str = json.dumps(correlations, default=str)
            intelligence_summary = json.dumps({
                "source": intelligence_data.get("source", "unknown"),
                "confidence": intelligence_data.get("confidence", 0.0),
                "record_count": len(intelligence_data.get("primary_data", []))
            }, default=str)
            
            response = await self.llm.ainvoke(
                assessment_prompt.format_messages(
                    correlations=correlations_str,
                    intelligence_summary=intelligence_summary
                )
            )
            
            threat_assessment = self._parse_llm_response(response.content)
            state["context"]["threat_assessment"] = threat_assessment
            
            logger.info("Threat assessment completed")
            
        except Exception as e:
            state = await self.handle_error(state, e)
        
        return state
    
    async def _generate_analysis(self, state: AgentState) -> AgentState:
        """Generate final threat intelligence analysis."""
        query = state["query"]
        analysis_depth = state["context"].get("analysis_depth", "operational")
        threat_assessment = state["context"].get("threat_assessment", {})
        correlations = state["context"].get("correlations", {})
        intelligence_data = state["context"].get("intelligence_data", {})
        
        try:
            if analysis_depth == "strategic":
                analysis_template = self._get_strategic_analysis_template()
            elif analysis_depth == "tactical":
                analysis_template = self._get_tactical_analysis_template()
            else:
                analysis_template = self._get_operational_analysis_template()
            
            analysis_prompt = self.create_prompt_template(analysis_template)
            
            response = await self.llm.ainvoke(
                analysis_prompt.format_messages(
                    query=query,
                    threat_assessment=json.dumps(threat_assessment, default=str),
                    correlations=json.dumps(correlations, default=str),
                    intelligence_summary=json.dumps({
                        "primary_data_count": len(intelligence_data.get("primary_data", [])),
                        "source_confidence": intelligence_data.get("confidence", 0.0),
                        "data_source": intelligence_data.get("source", "unknown")
                    }, default=str)
                )
            )
            
            # Structure the analysis results
            analysis_results = [
                {
                    "type": "threat_intelligence_analysis",
                    "query": query,
                    "analysis_depth": analysis_depth,
                    "content": response.content,
                    "threat_assessment": threat_assessment,
                    "correlations": correlations,
                    "data_sources": intelligence_data.get("source", "unknown"),
                    "confidence": intelligence_data.get("confidence", 0.0),
                    "timestamp": state["metadata"]["start_time"]
                }
            ]
            
            # Add raw intelligence data as supporting evidence
            if intelligence_data.get("primary_data"):
                analysis_results.extend(intelligence_data["primary_data"][:10])  # Top 10 records
            
            state["results"] = analysis_results
            logger.info(f"Threat intelligence analysis generated: {len(analysis_results)} results")
            
        except Exception as e:
            state = await self.handle_error(state, e)
        
        return state
    
    def _get_strategic_analysis_template(self) -> str:
        """Strategic level analysis template."""
        return """
        Generate a strategic threat intelligence analysis for this query:
        
        Query: {query}
        
        Threat Assessment: {threat_assessment}
        
        Correlations: {correlations}
        
        Intelligence Summary: {intelligence_summary}
        
        Provide strategic analysis including:
        1. Executive Summary (high-level threats and implications)
        2. Threat Landscape Overview (emerging trends, actor evolution)
        3. Geopolitical Context (nation-state activities, regional tensions)
        4. Sector Impact Analysis (affected industries and critical infrastructure)
        5. Long-term Threat Predictions (6-12 month outlook)
        6. Strategic Recommendations (policy, investment, partnerships)
        7. Collection Priorities (intelligence gaps and requirements)
        
        Format for executive briefing with clear risk ratings and actionable insights.
        """
    
    def _get_operational_analysis_template(self) -> str:
        """Operational level analysis template."""
        return """
        Generate an operational threat intelligence analysis for this query:
        
        Query: {query}
        
        Threat Assessment: {threat_assessment}
        
        Correlations: {correlations}
        
        Intelligence Summary: {intelligence_summary}
        
        Provide operational analysis including:
        1. Threat Summary (key actors, campaigns, TTPs)
        2. Attack Patterns (methods, tools, infrastructure)
        3. Targeting Analysis (victim selection, attack vectors)
        4. Timeline Analysis (attack progression, campaign evolution)
        5. Attribution Assessment (confidence levels, evidence)
        6. Defensive Recommendations (detection, mitigation, response)
        7. Threat Hunting Guidance (indicators, behaviors, techniques)
        
        Format for security operations teams with actionable technical details.
        """
    
    def _get_tactical_analysis_template(self) -> str:
        """Tactical level analysis template."""
        return """
        Generate a tactical threat intelligence analysis for this query:
        
        Query: {query}
        
        Threat Assessment: {threat_assessment}
        
        Correlations: {correlations}
        
        Intelligence Summary: {intelligence_summary}
        
        Provide tactical analysis including:
        1. Immediate Threats (active campaigns, imminent attacks)
        2. Technical Indicators (IOCs, signatures, artifacts)
        3. Attack Techniques (specific TTPs, tool usage)
        4. Infrastructure Analysis (C2 servers, domains, IPs)
        5. Malware Analysis (families, variants, capabilities)
        6. Countermeasures (blocking, detection rules, patches)
        7. Incident Response Guidance (containment, eradication, recovery)
        
        Format for immediate tactical response with specific technical details.
        """
    
    async def _search_threat_actors(self, query: str) -> Dict[str, Any]:
        """Search for threat actor intelligence."""
        # This would integrate with threat intelligence feeds
        # For now, return structured placeholder
        return {
            "search_type": "threat_actors",
            "query": query,
            "results": f"Threat actor search for: {query}",
            "confidence": 0.7
        }
    
    async def _analyze_campaign(self, query: str) -> Dict[str, Any]:
        """Analyze threat campaign details."""
        return {
            "search_type": "campaign_analysis",
            "query": query,
            "results": f"Campaign analysis for: {query}",
            "confidence": 0.7
        }
    
    async def _correlate_threats(self, query: str) -> Dict[str, Any]:
        """Correlate threats across sources."""
        return {
            "search_type": "threat_correlation",
            "query": query,
            "results": f"Threat correlation for: {query}",
            "confidence": 0.6
        }
    
    async def _assess_threat_landscape(self, query: str) -> Dict[str, Any]:
        """Assess current threat landscape."""
        return {
            "search_type": "landscape_assessment",
            "query": query,
            "results": f"Threat landscape assessment for: {query}",
            "confidence": 0.8
        }
    
    async def _extract_iocs(self, query: str) -> Dict[str, Any]:
        """Extract Indicators of Compromise."""
        return {
            "search_type": "ioc_extraction",
            "query": query,
            "results": f"IOC extraction for: {query}",
            "confidence": 0.9
        }
    
    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response, handling both JSON and text formats."""
        try:
            # Try to parse as JSON first
            if response.strip().startswith('{'):
                return json.loads(response)
        except json.JSONDecodeError:
            pass
        
        # Fallback to structured text parsing
        return {
            "content": response,
            "parsed": False,
            "format": "text"
        }
    
    def _should_continue(self, state: AgentState) -> str:
        """Determine if processing should continue."""
        if state.get("error"):
            return "error"
        
        if not state.get("query"):
            return "end"
        
        return "gather_intelligence"
    
    def _should_retry(self, state: AgentState) -> str:
        """Determine if processing should retry."""
        if state.get("error") and state.get("retry_count", 0) < state.get("max_retries", 3):
            return "retry"
        
        if state.get("error"):
            return "error"
        
        return "end"
    
    async def _handle_agent_error(self, state: AgentState) -> AgentState:
        """Handle agent-specific errors."""
        error = state.get("error", "Unknown error")
        retry_count = state.get("retry_count", 0)
        
        logger.error(f"ThreatIntelligenceAgent error (attempt {retry_count}): {error}")
        
        # Provide fallback results
        state["results"] = [{
            "type": "error_response",
            "message": f"Threat intelligence analysis failed: {error}",
            "retry_count": retry_count,
            "fallback_available": False
        }]
        
        state["confidence"] = 0.0
        return state
    
    async def process_query(self, state: AgentState) -> AgentState:
        """
        Process query using the full threat intelligence workflow.
        This method is called by the base class execute method.
        """
        # The processing is handled by the graph workflow
        # This method serves as the entry point
        return state