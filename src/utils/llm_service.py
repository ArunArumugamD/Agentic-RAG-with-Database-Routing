import asyncio
from typing import List, Dict, Any, Optional
import logging
from abc import ABC, abstractmethod
from config.settings import settings

logger = logging.getLogger(__name__)


class BaseLLMProvider(ABC):
    """Base class for LLM providers"""
    
    @abstractmethod
    async def generate_response(self, prompt: str, **kwargs) -> str:
        pass
    
    @abstractmethod
    async def generate_embedding(self, text: str) -> List[float]:
        pass


class GroqProvider(BaseLLMProvider):
    """Groq cloud LLM provider - free and fast"""
    
    def __init__(self):
        from groq import AsyncGroq
        self.client = AsyncGroq(api_key=settings.GROQ_API_KEY)
        self.embedding_model = None
        
    async def initialize_embedding_model(self):
        """Initialize sentence transformers for embeddings"""
        if not self.embedding_model:
            try:
                from sentence_transformers import SentenceTransformer
                self.embedding_model = SentenceTransformer(settings.EMBEDDING_MODEL)
                logger.info(f"Embedding model loaded: {settings.EMBEDDING_MODEL}")
            except Exception as e:
                logger.error(f"Failed to load embedding model: {e}")
                raise
    
    async def generate_response(self, prompt: str, **kwargs) -> str:
        """Generate response using Groq"""
        try:
            response = await self.client.chat.completions.create(
                model=settings.LLM_MODEL,
                messages=[{
                    'role': 'system',
                    'content': 'You are an expert cybersecurity analyst specializing in threat intelligence. Provide accurate, technical responses based on the given information.'
                }, {
                    'role': 'user',
                    'content': prompt
                }],
                temperature=kwargs.get('temperature', settings.TEMPERATURE),
                max_tokens=kwargs.get('max_tokens', settings.MAX_TOKENS),
            )
            
            return response.choices[0].message.content
            
        except Exception as e:
            logger.error(f"Groq generation failed: {e}")
            raise
    
    async def generate_embedding(self, text: str) -> List[float]:
        """Generate embeddings using sentence transformers"""
        await self.initialize_embedding_model()
        
        try:
            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            embedding = await loop.run_in_executor(
                None, 
                self.embedding_model.encode, 
                text
            )
            return embedding.tolist()
            
        except Exception as e:
            logger.error(f"Embedding generation failed: {e}")
            raise


class OllamaProvider(BaseLLMProvider):
    """Ollama local LLM provider - completely free"""
    
    def __init__(self):
        import ollama
        self.client = ollama.AsyncClient(host=settings.OLLAMA_BASE_URL)
        self.embedding_model = None
        
    async def initialize_embedding_model(self):
        """Initialize sentence transformers for embeddings"""
        if not self.embedding_model:
            try:
                from sentence_transformers import SentenceTransformer
                self.embedding_model = SentenceTransformer(settings.EMBEDDING_MODEL)
                logger.info(f"Embedding model loaded: {settings.EMBEDDING_MODEL}")
            except Exception as e:
                logger.error(f"Failed to load embedding model: {e}")
                raise
    
    async def generate_response(self, prompt: str, **kwargs) -> str:
        """Generate response using Ollama"""
        try:
            response = await self.client.chat(
                model=settings.LLM_MODEL,
                messages=[{
                    'role': 'user',
                    'content': prompt
                }],
                options={
                    'temperature': kwargs.get('temperature', settings.TEMPERATURE),
                    'num_predict': kwargs.get('max_tokens', settings.MAX_TOKENS),
                }
            )
            
            return response['message']['content']
            
        except Exception as e:
            logger.error(f"Ollama generation failed: {e}")
            raise
    
    async def generate_embedding(self, text: str) -> List[float]:
        """Generate embeddings using sentence transformers"""
        await self.initialize_embedding_model()
        
        try:
            # Run in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            embedding = await loop.run_in_executor(
                None, 
                self.embedding_model.encode, 
                text
            )
            return embedding.tolist()
            
        except Exception as e:
            logger.error(f"Embedding generation failed: {e}")
            raise


class HuggingFaceProvider(BaseLLMProvider):
    """Hugging Face provider with free tier"""
    
    def __init__(self):
        from transformers import AutoTokenizer, AutoModelForCausalLM
        import torch
        
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        self.tokenizer = None
        self.model = None
        self.embedding_model = None
        
    async def initialize_models(self):
        """Initialize models lazily"""
        if not self.model:
            try:
                from transformers import AutoTokenizer, AutoModelForCausalLM
                
                self.tokenizer = AutoTokenizer.from_pretrained(settings.HF_MODEL)
                self.model = AutoModelForCausalLM.from_pretrained(
                    settings.HF_MODEL,
                    torch_dtype="auto" if self.device == "cuda" else None
                )
                self.model.to(self.device)
                
                logger.info(f"HF model loaded: {settings.HF_MODEL}")
                
            except Exception as e:
                logger.error(f"Failed to load HF model: {e}")
                raise
        
        if not self.embedding_model:
            try:
                from sentence_transformers import SentenceTransformer
                self.embedding_model = SentenceTransformer(settings.EMBEDDING_MODEL)
                logger.info(f"Embedding model loaded: {settings.EMBEDDING_MODEL}")
            except Exception as e:
                logger.error(f"Failed to load embedding model: {e}")
                raise
    
    async def generate_response(self, prompt: str, **kwargs) -> str:
        """Generate response using Hugging Face model"""
        await self.initialize_models()
        
        try:
            import torch
            
            inputs = self.tokenizer.encode(prompt, return_tensors="pt").to(self.device)
            
            loop = asyncio.get_event_loop()
            
            def generate():
                with torch.no_grad():
                    outputs = self.model.generate(
                        inputs,
                        max_length=kwargs.get('max_tokens', settings.MAX_TOKENS),
                        temperature=kwargs.get('temperature', settings.TEMPERATURE),
                        do_sample=True,
                        pad_token_id=self.tokenizer.eos_token_id
                    )
                return self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            
            response = await loop.run_in_executor(None, generate)
            
            # Remove the original prompt from response
            if response.startswith(prompt):
                response = response[len(prompt):].strip()
                
            return response
            
        except Exception as e:
            logger.error(f"HuggingFace generation failed: {e}")
            raise
    
    async def generate_embedding(self, text: str) -> List[float]:
        """Generate embeddings using sentence transformers"""
        await self.initialize_models()
        
        try:
            loop = asyncio.get_event_loop()
            embedding = await loop.run_in_executor(
                None, 
                self.embedding_model.encode, 
                text
            )
            return embedding.tolist()
            
        except Exception as e:
            logger.error(f"Embedding generation failed: {e}")
            raise


class LLMService:
    """Main LLM service that manages different providers"""
    
    def __init__(self):
        self.provider: Optional[BaseLLMProvider] = None
        self._initialize_provider()
    
    def _initialize_provider(self):
        """Initialize the appropriate provider based on settings"""
        try:
            if settings.LLM_PROVIDER.lower() == "groq":
                self.provider = GroqProvider()
                logger.info("Using Groq provider")
            elif settings.LLM_PROVIDER.lower() == "ollama":
                self.provider = OllamaProvider()
                logger.info("Using Ollama provider")
            elif settings.LLM_PROVIDER.lower() == "huggingface":
                self.provider = HuggingFaceProvider()
                logger.info("Using HuggingFace provider")
            else:
                raise ValueError(f"Unknown LLM provider: {settings.LLM_PROVIDER}")
                
        except Exception as e:
            logger.error(f"Failed to initialize LLM provider: {e}")
            # Fallback to Groq (fastest and most reliable)
            self.provider = GroqProvider()
            logger.info("Falling back to Groq provider")
    
    async def generate_response(
        self,
        prompt: str,
        temperature: Optional[float] = None,
        max_tokens: Optional[int] = None,
        **kwargs
    ) -> str:
        """Generate a response using the configured provider"""
        if not self.provider:
            raise RuntimeError("No LLM provider initialized")
        
        generation_kwargs = kwargs.copy()
        if temperature is not None:
            generation_kwargs['temperature'] = temperature
        if max_tokens is not None:
            generation_kwargs['max_tokens'] = max_tokens
            
        return await self.provider.generate_response(prompt, **generation_kwargs)
    
    async def generate_embedding(self, text: str) -> List[float]:
        """Generate embeddings using the configured provider"""
        if not self.provider:
            raise RuntimeError("No LLM provider initialized")
        
        return await self.provider.generate_embedding(text)
    
    async def batch_generate_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings for multiple texts"""
        embeddings = []
        for text in texts:
            embedding = await self.generate_embedding(text)
            embeddings.append(embedding)
        return embeddings


# Global LLM service instance
llm_service = LLMService()