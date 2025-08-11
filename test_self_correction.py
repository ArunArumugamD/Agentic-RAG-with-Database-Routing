#!/usr/bin/env python3
"""
Test script for self-correction mechanisms in the routing engine
"""

import asyncio
import sys
from pathlib import Path

# Add src to Python path
sys.path.insert(0, str(Path(__file__).parent))

from src.routing import SelfCorrectingRouteEngine
from src.database.connection import db_manager


async def test_self_correction():
    """Test various scenarios that should trigger self-correction"""
    
    print("[INFO] Testing Self-Correction Mechanisms")
    print("=" * 50)
    
    # Initialize route engine
    route_engine = SelfCorrectingRouteEngine()
    
    # Test queries that should trigger different correction strategies
    test_queries = [
        {
            "query": "Show me all vulnerabilities from 2019",  # Too old, should trigger temporal adjustment
            "expected_correction": "temporal_adjustment",
            "description": "Query with outdated temporal reference"
        },
        {
            "query": "ransomware",  # Too general, should trigger synonym enrichment
            "expected_correction": "use_synonyms",
            "description": "Single-word general query"
        },
        {
            "query": "CVE-9999-9999",  # Non-existent CVE, should trigger reformulation
            "expected_correction": "reformulate_query",
            "description": "Query for non-existent CVE"
        },
        {
            "query": "Show me critical vulnerabilities in Apache and also recent threat actors targeting financial sector",  # Complex, should decompose
            "expected_correction": "decompose_query",
            "description": "Complex multi-part query"
        },
        {
            "query": "cybersecurity threats with severity greater than 9.5 from vendor Microsoft in last 7 days",  # Very specific, should relax filters
            "expected_correction": "relax_filters",
            "description": "Over-constrained query"
        }
    ]
    
    for test_case in test_queries:
        print(f"\n[TEST] {test_case['description']}")
        print(f"Query: {test_case['query']}")
        print("-" * 40)
        
        try:
            # Execute query with routing
            result = await route_engine.route_and_execute(
                query=test_case['query'],
                mode="balanced"
            )
            
            # Check results
            metadata = result.get("metadata", {})
            
            print(f"Results found: {metadata.get('result_count', 0)}")
            print(f"Relevance score: {metadata.get('relevance_score', 0):.2f}")
            print(f"Self-corrected: {metadata.get('self_corrected', False)}")
            print(f"Sources used: {metadata.get('sources_used', [])}")
            print(f"Response time: {metadata.get('response_time_ms', 0)}ms")
            
            if metadata.get('self_corrected'):
                print("[SUCCESS] Self-correction was triggered")
            
            # Show sample results if any
            if result.get("results"):
                print(f"\nSample result: {str(result['results'][0])[:200]}...")
            
        except Exception as e:
            print(f"[ERROR] Test failed: {str(e)}")
    
    print("\n" + "=" * 50)
    print("[INFO] Self-Correction Testing Complete")


async def test_grading_accuracy():
    """Test the grading system's accuracy"""
    
    print("\n[INFO] Testing Grading Accuracy")
    print("=" * 50)
    
    from src.routing.self_correction import self_corrector
    
    # Test with good results
    good_results = [
        {
            "cve_id": "CVE-2024-1234",
            "severity": "critical",
            "description": "Remote code execution vulnerability in Apache",
            "cvss_score": 9.8
        },
        {
            "cve_id": "CVE-2024-5678",
            "severity": "high",
            "description": "SQL injection vulnerability",
            "cvss_score": 8.5
        }
    ]
    
    grading = await self_corrector.grade_results(
        query="critical Apache vulnerabilities",
        results=good_results,
        expected_type="vulnerability"
    )
    
    print(f"Good results grading:")
    print(f"  Relevance: {grading.relevance_score:.2f}")
    print(f"  Completeness: {grading.completeness_score:.2f}")
    print(f"  Accuracy: {grading.accuracy_confidence:.2f}")
    print(f"  Issues: {grading.issues}")
    
    # Test with poor results
    poor_results = []
    
    grading = await self_corrector.grade_results(
        query="critical Apache vulnerabilities",
        results=poor_results,
        expected_type="vulnerability"
    )
    
    print(f"\nPoor results grading:")
    print(f"  Relevance: {grading.relevance_score:.2f}")
    print(f"  Completeness: {grading.completeness_score:.2f}")
    print(f"  Accuracy: {grading.accuracy_confidence:.2f}")
    print(f"  Issues: {grading.issues}")
    print(f"  Suggestions: {grading.suggestions}")


async def test_query_reformulation():
    """Test query reformulation capabilities"""
    
    print("\n[INFO] Testing Query Reformulation")
    print("=" * 50)
    
    from src.routing.self_correction import self_corrector
    
    test_cases = [
        {
            "original": "hack",
            "issues": ["Too vague", "No specific context"],
        },
        {
            "original": "CVE-9999-9999",
            "issues": ["No results found", "Invalid CVE ID"],
        },
        {
            "original": "latest threats",
            "issues": ["Too general", "No time frame specified"],
        }
    ]
    
    for test in test_cases:
        print(f"\nOriginal: {test['original']}")
        print(f"Issues: {test['issues']}")
        
        reformulated = await self_corrector.reformulate_query(
            original_query=test['original'],
            issues=test['issues']
        )
        
        print(f"Reformulated: {reformulated}")


async def main():
    """Run all tests"""
    
    # Initialize database connection
    await db_manager.initialize()
    
    try:
        # Run tests
        await test_grading_accuracy()
        await test_query_reformulation()
        await test_self_correction()
        
    finally:
        # Cleanup
        await db_manager.close()


if __name__ == "__main__":
    asyncio.run(main())