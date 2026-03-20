"""RAG configuration constants — paths, model names, retrieval params."""

import os
from dotenv import load_dotenv

# Load .env from config directory
_env_path = os.path.join(os.path.dirname(__file__), "..", "..", "config", ".env")
load_dotenv(_env_path)

# Paths
AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCUMENTS_DIR = os.path.join(AGENT_DIR, "documents")
CHROMA_PERSIST_DIR = os.path.join(AGENT_DIR, "vector_db")
BM25_PERSIST_PATH = os.path.join(AGENT_DIR, "bm25_index.pkl")

# Embedding model (local, free, CPU)
EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2"

# Chunking
CHUNK_SIZE = 500
CHUNK_OVERLAP = 100

# Retrieval
VECTOR_TOP_K = 5
BM25_TOP_K = 5
RRF_K = 60  # Standard RRF constant

# LLM (OpenRouter)
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_MODEL = os.getenv("MODEL_NAME", "anthropic/claude-sonnet-4.6")
LLM_TEMPERATURE = 0.1
LLM_MAX_TOKENS = 2000

# ChromaDB collection name
COLLECTION_NAME = "finnova_knowledge_base"
