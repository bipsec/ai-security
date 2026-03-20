"""BM25Okapi keyword index with pickle persistence."""

import os
import pickle
from typing import List, Tuple

from rank_bm25 import BM25Okapi

from ai_security_wrapper.agent.rag.config import BM25_PERSIST_PATH, BM25_TOP_K

_bm25_index = None
_corpus_docs = None  # parallel list of (doc_id, text, metadata)


def _tokenize(text: str) -> List[str]:
    """Simple whitespace tokenizer with lowercasing."""
    return text.lower().split()


def build_and_persist(docs) -> None:
    """Build BM25 index from LangChain Documents and pickle to disk."""
    global _bm25_index, _corpus_docs

    corpus_tokens = [_tokenize(d.page_content) for d in docs]
    _corpus_docs = [
        (d.metadata["doc_id"], d.page_content, d.metadata) for d in docs
    ]
    _bm25_index = BM25Okapi(corpus_tokens)

    with open(BM25_PERSIST_PATH, "wb") as f:
        pickle.dump({"index": _bm25_index, "corpus_docs": _corpus_docs}, f)


def load_from_disk() -> bool:
    """Load pickled BM25 index. Returns True if successful."""
    global _bm25_index, _corpus_docs

    if not os.path.exists(BM25_PERSIST_PATH):
        return False

    with open(BM25_PERSIST_PATH, "rb") as f:
        data = pickle.load(f)

    _bm25_index = data["index"]
    _corpus_docs = data["corpus_docs"]
    return True


def is_populated() -> bool:
    """Check whether the BM25 index is loaded."""
    return _bm25_index is not None and _corpus_docs is not None


def query(text: str, top_k: int = BM25_TOP_K) -> List[Tuple[str, str, dict]]:
    """Query BM25 and return top-k results as (doc_id, text, metadata)."""
    if not is_populated():
        return []

    tokens = _tokenize(text)
    scores = _bm25_index.get_scores(tokens)

    # Get top-k indices sorted by score descending
    top_indices = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)[:top_k]

    return [_corpus_docs[i] for i in top_indices if scores[i] > 0]
