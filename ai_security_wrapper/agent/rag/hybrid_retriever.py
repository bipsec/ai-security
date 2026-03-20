"""Hybrid retriever combining ChromaDB vector search and BM25 via RRF."""

from collections import defaultdict
from typing import List

from langchain_core.callbacks import CallbackManagerForRetrieverRun
from langchain_core.documents import Document
from langchain_core.retrievers import BaseRetriever

from ai_security_wrapper.agent.rag import bm25_store, vector_store
from ai_security_wrapper.agent.rag.config import BM25_TOP_K, RRF_K, VECTOR_TOP_K


class HybridRetriever(BaseRetriever):
    """LangChain-compatible retriever using RRF fusion of vector + BM25."""

    vector_top_k: int = VECTOR_TOP_K
    bm25_top_k: int = BM25_TOP_K
    rrf_k: int = RRF_K

    def _get_relevant_documents(
        self, query: str, *, run_manager: CallbackManagerForRetrieverRun
    ) -> List[Document]:
        # Vector search
        vec_ids, vec_texts, vec_metas = vector_store.query(query, top_k=self.vector_top_k)

        # BM25 search
        bm25_results = bm25_store.query(query, top_k=self.bm25_top_k)

        # RRF fusion: score(doc) = sum(1 / (k + rank)) across rankers
        rrf_scores = defaultdict(float)
        doc_map = {}

        for rank, (doc_id, text, meta) in enumerate(zip(vec_ids, vec_texts, vec_metas)):
            rrf_scores[doc_id] += 1.0 / (self.rrf_k + rank + 1)
            doc_map[doc_id] = Document(page_content=text, metadata=meta)

        for rank, (doc_id, text, meta) in enumerate(bm25_results):
            rrf_scores[doc_id] += 1.0 / (self.rrf_k + rank + 1)
            if doc_id not in doc_map:
                doc_map[doc_id] = Document(page_content=text, metadata=meta)

        # Sort by fused score descending, return top results
        sorted_ids = sorted(rrf_scores, key=rrf_scores.get, reverse=True)
        top_k = max(self.vector_top_k, self.bm25_top_k)
        return [doc_map[did] for did in sorted_ids[:top_k]]
