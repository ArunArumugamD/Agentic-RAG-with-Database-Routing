"""
Base agent class for LangGraph-based autonomous decision making.
Provides foundation for specialized cybersecurity intelligence agents.
"""

import logging
from typing import Dict, Any, List, Optional, TypedDict
from abc import ABC, abstractmethod
from datetime import datetime
import json

from langchain.schema import BaseMessage
from langchain_openai import ChatOpenAI
from langchain.prompts import ChatPromptTemplate
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolExecutor

from config.settings import settings

logger = logging.getLogger(__name__)


class AgentState(TypedDict):
    """Base state structure for all agents."""
    messages: List[BaseMessage]
    query: str
    context: Dict[str, Any]
    results: List[Dict[str, Any]]
    confidence: float
    metadata: Dict[str, Any]
    error: Optional[str]
    retry_count: int
    max_retries: int


class BaseAgent(ABC):
    """
    Abstract base class for cybersecurity intelligence agents.
    Implements common patterns and LangGraph integration.
    """
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.llm = self._initialize_llm()
        self.graph = None
        self.execution_stats = {
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "average_confidence": 0.0
        }
        
    def _initialize_llm(self) -> ChatOpenAI:
        """Initialize the language model with cybersecurity-optimized settings."""
        return ChatOpenAI(
            model=settings.openai_model,
            temperature=settings.openai_temperature,
            max_tokens=settings.openai_max_tokens,
            openai_api_key=settings.openai_api_key
        )
    
    @abstractmethod
    def create_graph(self) -> StateGraph:
        """Create the agent's decision graph. Must be implemented by subclasses."""
        pass
    
    @abstractmethod
    async def process_query(self, state: AgentState) -> AgentState:
        """Process the main query. Must be implemented by subclasses."""
        pass
    
    def initialize(self):
        """Initialize the agent and compile the graph."""
        try:
            self.graph = self.create_graph()
            self.graph = self.graph.compile()
            logger.info(f"Agent '{self.name}' initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize agent '{self.name}': {str(e)}")
            raise
    
    async def execute(self, query: str, context: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Execute the agent workflow.
        
        Args:
            query: User query string
            context: Optional context for the query
            
        Returns:
            Execution results with metadata
        """
        if not self.graph:
            raise RuntimeError(f"Agent '{self.name}' not initialized")
        
        start_time = datetime.utcnow()
        self.execution_stats["total_executions"] += 1
        
        try:
            # Initialize state
            initial_state = AgentState(
                messages=[],
                query=query,
                context=context or {},
                results=[],
                confidence=0.0,
                metadata={"agent": self.name, "start_time": start_time.isoformat()},
                error=None,
                retry_count=0,
                max_retries=settings.max_retries
            )
            
            # Execute the graph
            final_state = await self.graph.ainvoke(initial_state)
            
            # Calculate execution time
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Update statistics
            if final_state.get("error"):
                self.execution_stats["failed_executions"] += 1
            else:
                self.execution_stats["successful_executions"] += 1
                # Update average confidence
                total_successful = self.execution_stats["successful_executions"]
                current_avg = self.execution_stats["average_confidence"]
                new_confidence = final_state.get("confidence", 0.0)
                self.execution_stats["average_confidence"] = (
                    (current_avg * (total_successful - 1) + new_confidence) / total_successful
                )
            
            # Prepare response
            response = {
                "agent": self.name,
                "query": query,
                "results": final_state.get("results", []),
                "confidence": final_state.get("confidence", 0.0),
                "metadata": {
                    **final_state.get("metadata", {}),
                    "execution_time": execution_time,
                    "retry_count": final_state.get("retry_count", 0)
                },
                "error": final_state.get("error"),
                "success": final_state.get("error") is None
            }
            
            logger.info(f"Agent '{self.name}' executed successfully in {execution_time:.2f}s")
            return response
            
        except Exception as e:
            self.execution_stats["failed_executions"] += 1
            execution_time = (datetime.utcnow() - start_time).total_seconds()
            
            logger.error(f"Agent '{self.name}' execution failed: {str(e)}")
            return {
                "agent": self.name,
                "query": query,
                "results": [],
                "confidence": 0.0,
                "metadata": {
                    "execution_time": execution_time,
                    "error_type": type(e).__name__
                },
                "error": str(e),
                "success": False
            }
    
    async def validate_results(self, state: AgentState) -> AgentState:
        """
        Validate and grade the quality of results.
        Common validation logic for all agents.
        """
        results = state.get("results", [])
        
        if not results:
            state["confidence"] = 0.0
            state["metadata"]["validation"] = "No results to validate"
            return state
        
        # Basic validation metrics
        validation_metrics = {
            "result_count": len(results),
            "has_cybersec_context": False,
            "has_structured_data": False,
            "completeness_score": 0.0
        }
        
        cybersec_keywords = [
            "vulnerability", "threat", "attack", "malware", "exploit",
            "cve", "security", "breach", "incident", "risk"
        ]
        
        # Check for cybersecurity context
        result_text = " ".join(str(v) for result in results for v in result.values()).lower()
        validation_metrics["has_cybersec_context"] = any(
            keyword in result_text for keyword in cybersec_keywords
        )
        
        # Check for structured data
        validation_metrics["has_structured_data"] = any(
            isinstance(result, dict) and len(result) > 2 
            for result in results
        )
        
        # Calculate completeness score
        avg_fields_per_result = sum(
            len(result) if isinstance(result, dict) else 1 
            for result in results
        ) / len(results)
        validation_metrics["completeness_score"] = min(avg_fields_per_result / 10, 1.0)
        
        # Calculate overall confidence
        confidence_factors = [
            0.3 if validation_metrics["has_cybersec_context"] else 0.0,
            0.2 if validation_metrics["has_structured_data"] else 0.0,
            validation_metrics["completeness_score"] * 0.3,
            min(len(results) / 10, 1.0) * 0.2  # Result quantity factor
        ]
        
        state["confidence"] = sum(confidence_factors)
        state["metadata"]["validation"] = validation_metrics
        
        return state
    
    async def handle_error(self, state: AgentState, error: Exception) -> AgentState:
        """
        Handle errors with retry logic and fallback strategies.
        """
        state["error"] = str(error)
        state["retry_count"] = state.get("retry_count", 0) + 1
        
        if state["retry_count"] < state.get("max_retries", 3):
            logger.warning(f"Agent '{self.name}' error (attempt {state['retry_count']}): {str(error)}")
            # Clear error for retry
            state["error"] = None
            return state
        else:
            logger.error(f"Agent '{self.name}' failed after {state['retry_count']} attempts: {str(error)}")
            state["confidence"] = 0.0
            return state
    
    def get_system_prompt(self) -> str:
        """
        Get the system prompt for this agent.
        Override in subclasses for specialized prompts.
        """
        return f"""
        You are {self.name}, a specialized cybersecurity intelligence agent.
        
        Description: {self.description}
        
        Your role is to:
        1. Analyze cybersecurity-related queries with expert knowledge
        2. Provide accurate, actionable intelligence
        3. Focus on threat analysis, vulnerability assessment, and risk evaluation
        4. Always consider the latest threat landscape and attack techniques
        5. Prioritize critical security information and time-sensitive threats
        
        Guidelines:
        - Be precise and factual in your analysis
        - Consider both technical and business impact
        - Provide context for threat actors, campaigns, and vulnerabilities
        - Include confidence levels and data sources when possible
        - Focus on actionable intelligence for security teams
        
        Current date: {datetime.utcnow().isoformat()}
        """
    
    def create_prompt_template(self, template_string: str) -> ChatPromptTemplate:
        """Create a chat prompt template with system context."""
        return ChatPromptTemplate.from_messages([
            ("system", self.get_system_prompt()),
            ("human", template_string)
        ])
    
    def get_execution_stats(self) -> Dict[str, Any]:
        """Get execution statistics for this agent."""
        stats = self.execution_stats.copy()
        if stats["total_executions"] > 0:
            stats["success_rate"] = stats["successful_executions"] / stats["total_executions"]
            stats["failure_rate"] = stats["failed_executions"] / stats["total_executions"]
        else:
            stats["success_rate"] = 0.0
            stats["failure_rate"] = 0.0
        
        return stats
    
    def reset_stats(self):
        """Reset execution statistics."""
        self.execution_stats = {
            "total_executions": 0,
            "successful_executions": 0,
            "failed_executions": 0,
            "average_confidence": 0.0
        }