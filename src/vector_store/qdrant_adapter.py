import asyncio
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import logging
import hashlib
import json

from qdrant_client import QdrantClient
from qdrant_client.http import models
from qdrant_client.http.models import Distance, VectorParams, PointStruct

from config.settings import settings
from src.utils.llm_service import llm_service

logger = logging.getLogger(__name__)


@dataclass
class SearchResult:
    """Search result from vector database"""
    content: str
    metadata: Dict[str, Any]
    score: float
    id: str


class QdrantAdapter:
    """Qdrant vector database adapter for threat intelligence documents"""
    
    def __init__(self):
        self.client = QdrantClient(
            host=settings.QDRANT_HOST,
            port=settings.QDRANT_PORT
        )
        self.collection_name = settings.QDRANT_COLLECTION_NAME
        self.embedding_dim = 384  # all-MiniLM-L6-v2 dimension
    
    async def initialize_collection(self):
        """Initialize Qdrant collection if it doesn't exist"""
        try:
            collections = self.client.get_collections().collections
            collection_names = [col.name for col in collections]
            
            if self.collection_name not in collection_names:
                self.client.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=VectorParams(
                        size=self.embedding_dim,
                        distance=Distance.COSINE
                    ),
                    optimizers_config=models.OptimizersConfig(
                        default_segment_number=2,
                        max_segment_size=20000,
                        memmap_threshold=20000,
                        indexing_threshold=20000,
                        flush_interval_sec=5
                    ),
                    hnsw_config=models.HnswConfig(
                        m=16,
                        ef_construct=100,
                        full_scan_threshold=10000,
                        max_indexing_threads=0
                    )
                )
                logger.info(f"Created Qdrant collection: {self.collection_name}")
            else:
                logger.info(f"Qdrant collection already exists: {self.collection_name}")
                
        except Exception as e:
            logger.error(f"Failed to initialize Qdrant collection: {e}")
            raise
    
    def _generate_doc_id(self, content: str, source: str) -> str:
        """Generate unique document ID"""
        combined = f"{source}:{content}"
        return hashlib.md5(combined.encode()).hexdigest()
    
    async def add_document(
        self,
        content: str,
        metadata: Dict[str, Any],
        doc_id: Optional[str] = None
    ) -> str:
        """Add a single document to the vector store"""
        try:
            # Generate embedding
            embedding = await llm_service.generate_embedding(content)
            
            # Generate ID if not provided
            if not doc_id:
                doc_id = self._generate_doc_id(content, metadata.get('source', 'unknown'))
            
            # Create point
            point = PointStruct(
                id=doc_id,
                vector=embedding,
                payload={
                    "content": content,
                    "metadata": metadata,
                    "content_length": len(content),
                    "doc_type": metadata.get('type', 'document')
                }
            )
            
            # Upsert to Qdrant
            self.client.upsert(
                collection_name=self.collection_name,
                points=[point]
            )
            
            logger.debug(f"Added document to Qdrant: {doc_id}")
            return doc_id
            
        except Exception as e:
            logger.error(f"Failed to add document to Qdrant: {e}")
            raise
    
    async def add_documents_batch(
        self,
        documents: List[Dict[str, Any]],
        batch_size: int = 100
    ) -> List[str]:
        """Add multiple documents in batches"""
        doc_ids = []
        
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]
            batch_points = []
            batch_ids = []
            
            # Generate embeddings for batch
            contents = [doc['content'] for doc in batch]
            embeddings = await llm_service.batch_generate_embeddings(contents)
            
            # Create points
            for doc, embedding in zip(batch, embeddings):
                doc_id = doc.get('id') or self._generate_doc_id(
                    doc['content'], 
                    doc.get('metadata', {}).get('source', 'unknown')
                )
                
                point = PointStruct(
                    id=doc_id,
                    vector=embedding,
                    payload={
                        "content": doc['content'],
                        "metadata": doc.get('metadata', {}),
                        "content_length": len(doc['content']),
                        "doc_type": doc.get('metadata', {}).get('type', 'document')
                    }
                )
                
                batch_points.append(point)
                batch_ids.append(doc_id)
            
            # Upsert batch
            try:
                self.client.upsert(
                    collection_name=self.collection_name,
                    points=batch_points
                )
                doc_ids.extend(batch_ids)
                logger.info(f"Added batch of {len(batch_points)} documents to Qdrant")
                
            except Exception as e:
                logger.error(f"Failed to add document batch: {e}")
                raise
        
        return doc_ids
    
    async def search_documents(
        self,
        query: str,
        limit: int = 10,
        score_threshold: float = 0.5,
        filter_conditions: Optional[Dict[str, Any]] = None
    ) -> List[SearchResult]:
        """Search for similar documents"""
        try:
            # Generate query embedding
            query_embedding = await llm_service.generate_embedding(query)
            
            # Build filter
            query_filter = None
            if filter_conditions:
                filter_clauses = []
                for key, value in filter_conditions.items():
                    if isinstance(value, list):
                        filter_clauses.append(
                            models.FieldCondition(
                                key=f"metadata.{key}",
                                match=models.MatchAny(any=value)
                            )
                        )
                    else:
                        filter_clauses.append(
                            models.FieldCondition(
                                key=f"metadata.{key}",
                                match=models.MatchValue(value=value)
                            )
                        )
                
                if filter_clauses:
                    query_filter = models.Filter(
                        must=filter_clauses
                    )
            
            # Search
            search_results = self.client.search(
                collection_name=self.collection_name,
                query_vector=query_embedding,
                query_filter=query_filter,
                limit=limit,
                score_threshold=score_threshold,
                with_payload=True,
                with_vectors=False
            )
            
            # Convert to SearchResult objects
            results = []
            for result in search_results:
                results.append(SearchResult(
                    content=result.payload["content"],
                    metadata=result.payload["metadata"],
                    score=result.score,
                    id=result.id
                ))
            
            logger.debug(f"Found {len(results)} documents for query: {query[:50]}")
            return results
            
        except Exception as e:
            logger.error(f"Document search failed: {e}")
            raise
    
    async def search_by_metadata(
        self,
        metadata_filters: Dict[str, Any],
        limit: int = 50
    ) -> List[SearchResult]:
        """Search documents by metadata only (no vector search)"""
        try:
            # Build filter conditions
            filter_clauses = []
            for key, value in metadata_filters.items():
                if isinstance(value, list):
                    filter_clauses.append(
                        models.FieldCondition(
                            key=f"metadata.{key}",
                            match=models.MatchAny(any=value)
                        )
                    )
                else:
                    filter_clauses.append(
                        models.FieldCondition(
                            key=f"metadata.{key}",
                            match=models.MatchValue(value=value)
                        )
                    )
            
            query_filter = models.Filter(must=filter_clauses) if filter_clauses else None
            
            # Scroll through results (no vector search)
            results, _ = self.client.scroll(
                collection_name=self.collection_name,
                scroll_filter=query_filter,
                limit=limit,
                with_payload=True,
                with_vectors=False
            )
            
            # Convert to SearchResult objects
            search_results = []
            for result in results:
                search_results.append(SearchResult(
                    content=result.payload["content"],
                    metadata=result.payload["metadata"],
                    score=1.0,  # No scoring for metadata-only search
                    id=result.id
                ))
            
            logger.debug(f"Found {len(search_results)} documents by metadata")
            return search_results
            
        except Exception as e:
            logger.error(f"Metadata search failed: {e}")
            raise
    
    async def get_document_by_id(self, doc_id: str) -> Optional[SearchResult]:
        """Retrieve a specific document by ID"""
        try:
            result = self.client.retrieve(
                collection_name=self.collection_name,
                ids=[doc_id],
                with_payload=True,
                with_vectors=False
            )
            
            if result:
                point = result[0]
                return SearchResult(
                    content=point.payload["content"],
                    metadata=point.payload["metadata"],
                    score=1.0,
                    id=point.id
                )
            
            return None
            
        except Exception as e:
            logger.error(f"Document retrieval failed: {e}")
            raise
    
    async def delete_document(self, doc_id: str) -> bool:
        """Delete a document by ID"""
        try:
            self.client.delete(
                collection_name=self.collection_name,
                points_selector=models.PointIdsList(
                    points=[doc_id]
                )
            )
            logger.debug(f"Deleted document: {doc_id}")
            return True
            
        except Exception as e:
            logger.error(f"Document deletion failed: {e}")
            return False
    
    async def get_collection_info(self) -> Dict[str, Any]:
        """Get collection statistics"""
        try:
            info = self.client.get_collection(self.collection_name)
            return {
                "total_documents": info.points_count,
                "vector_size": info.config.params.vectors.size,
                "distance_metric": info.config.params.vectors.distance.value,
                "status": info.status.value
            }
            
        except Exception as e:
            logger.error(f"Failed to get collection info: {e}")
            return {}
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Qdrant health"""
        try:
            collections = self.client.get_collections()
            collection_exists = any(
                col.name == self.collection_name 
                for col in collections.collections
            )
            
            if collection_exists:
                info = await self.get_collection_info()
                return {
                    "status": "healthy",
                    "collection_exists": True,
                    "document_count": info.get("total_documents", 0)
                }
            else:
                return {
                    "status": "unhealthy",
                    "collection_exists": False,
                    "error": f"Collection '{self.collection_name}' not found"
                }
                
        except Exception as e:
            logger.error(f"Qdrant health check failed: {e}")
            return {
                "status": "unhealthy",
                "error": str(e)
            }


# Global Qdrant adapter instance
qdrant_adapter = QdrantAdapter()