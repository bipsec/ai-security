"""ChromaDB persistent vector store for document embeddings."""

import chromadb

from ai_security_wrapper.agent.rag.config import (
    CHROMA_PERSIST_DIR,
    COLLECTION_NAME,
    VECTOR_TOP_K,
)
from ai_security_wrapper.agent.rag.embeddings import get_embedding_function

_client = None
_collection = None


def _get_collection():
    """Return the ChromaDB collection, creating it if needed."""
    global _client, _collection
    if _collection is None:
        _client = chromadb.PersistentClient(path=CHROMA_PERSIST_DIR)
        _collection = _client.get_or_create_collection(
            name=COLLECTION_NAME,
            embedding_function=get_embedding_function(),
        )
    return _collection


def is_populated() -> bool:
    """Check whether the vector store already has documents."""
    return _get_collection().count() > 0


def add_documents(docs) -> None:
    """Add LangChain Document objects to the vector store."""
    collection = _get_collection()
    texts = [d.page_content for d in docs]
    metadatas = [d.metadata for d in docs]
    ids = [d.metadata["doc_id"] for d in docs]
    # ChromaDB has a batch limit; process in chunks of 500
    batch_size = 500
    for i in range(0, len(texts), batch_size):
        collection.add(
            documents=texts[i : i + batch_size],
            metadatas=metadatas[i : i + batch_size],
            ids=ids[i : i + batch_size],
        )


def query(text: str, top_k: int = VECTOR_TOP_K):
    """Query the vector store and return (doc_ids, documents, metadatas)."""
    collection = _get_collection()
    results = collection.query(query_texts=[text], n_results=top_k)
    return (
        results["ids"][0],
        results["documents"][0],
        results["metadatas"][0],
    )
