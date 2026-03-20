"""SentenceTransformer embedding wrapper for ChromaDB and LangChain."""

from chromadb.utils.embedding_functions import SentenceTransformerEmbeddingFunction

from ai_security_wrapper.agent.rag.config import EMBEDDING_MODEL_NAME

# Lazy-loaded singleton
_embedding_fn = None


def get_embedding_function() -> SentenceTransformerEmbeddingFunction:
    """Return a ChromaDB-compatible SentenceTransformer embedding function."""
    global _embedding_fn
    if _embedding_fn is None:
        _embedding_fn = SentenceTransformerEmbeddingFunction(
            model_name=EMBEDDING_MODEL_NAME,
        )
    return _embedding_fn
