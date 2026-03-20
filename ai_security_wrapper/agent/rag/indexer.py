"""Lazy singleton orchestrator — build or load indexes, return RAG chain."""

import logging

from ai_security_wrapper.agent.rag import bm25_store, vector_store
from ai_security_wrapper.agent.rag.chain import build_chain, build_raw_chain
from ai_security_wrapper.agent.rag.document_loader import load_all_documents
from ai_security_wrapper.agent.rag.hybrid_retriever import HybridRetriever

logger = logging.getLogger(__name__)

_chain = None
_raw_chain = None
_retriever = None


def _ensure_indexes():
    """Load or build indexes, create retriever."""
    global _retriever

    if _retriever is not None:
        return

    # Check if indexes already exist on disk
    vector_ready = vector_store.is_populated()
    bm25_ready = bm25_store.load_from_disk()

    if not vector_ready or not bm25_ready:
        logger.info("Building RAG indexes from knowledge base documents...")
        docs = load_all_documents()
        logger.info("Loaded %d document chunks.", len(docs))

        if not vector_ready:
            vector_store.add_documents(docs)
            logger.info("ChromaDB vector store populated.")

        if not bm25_ready:
            bm25_store.build_and_persist(docs)
            logger.info("BM25 index built and persisted.")
    else:
        logger.info("RAG indexes loaded from disk.")

    _retriever = HybridRetriever()


def get_chain():
    """Return a cached SECURED RAG chain (with Context Guard)."""
    global _chain
    if _chain is not None:
        return _chain

    _ensure_indexes()
    _chain = build_chain(_retriever)
    return _chain


def get_raw_chain():
    """Return a cached RAW RAG chain (without Context Guard, for demo)."""
    global _raw_chain
    if _raw_chain is not None:
        return _raw_chain

    _ensure_indexes()
    _raw_chain = build_raw_chain(_retriever)
    return _raw_chain


def get_retriever() -> HybridRetriever:
    """Return the hybrid retriever directly (for context visibility in UIs)."""
    _ensure_indexes()
    return _retriever
