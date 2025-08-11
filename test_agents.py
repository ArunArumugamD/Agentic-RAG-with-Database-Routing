#!/usr/bin/env python3
"""
Quick test script to verify our agents work with free LLMs
"""

import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent))

async def test_agents():
    """Test agent imports and basic functionality"""
    
    print("Testing agent imports...")
    
    try:
        # Test base agent
        from src.agents.base_agent import BaseAgent, FreeLLMWrapper
        print("[SUCCESS] BaseAgent and FreeLLMWrapper imported successfully")
        
        # Test LLM wrapper
        llm = FreeLLMWrapper()
        print("[SUCCESS] FreeLLMWrapper initialized successfully")
        
        # Test LLM call
        response = await llm._acall("What is cybersecurity?")
        print(f"[SUCCESS] LLM response: {response[:100]}...")
        
        # Test routing engine import
        from src.routing import SelfCorrectingRouteEngine
        print("[SUCCESS] SelfCorrectingRouteEngine imported successfully")
        
        # Test specialized agents import
        from src.agents.threat_intelligence_agent import ThreatIntelligenceAgent
        from src.agents.vulnerability_agent import VulnerabilityAgent
        from src.agents.agent_coordinator import AgentCoordinator
        print("[SUCCESS] All specialized agents imported successfully")
        
        print("\n[SUCCESS] All agent imports and basic tests passed!")
        
    except Exception as e:
        print(f"[ERROR] Test failed: {str(e)}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_agents())