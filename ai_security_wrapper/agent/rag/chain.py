"""LangChain RAG chain: retriever -> prompt -> LLM -> string output."""

from typing import Dict, List, Optional, Tuple

from langchain_core.documents import Document
from langchain_core.output_parsers import StrOutputParser
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.retrievers import BaseRetriever
from langchain_core.runnables import RunnableLambda, RunnablePassthrough
from langchain_openai import ChatOpenAI

from ai_security_wrapper.agent.rag.config import (
    LLM_MAX_TOKENS,
    LLM_TEMPERATURE,
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    OPENROUTER_MODEL,
)
from ai_security_wrapper.agent.rag.context_guard import (
    get_redacted_categories,
    sanitize_context,
)
from ai_security_wrapper.agent.rag.prompts import SYSTEM_PROMPT, USER_PROMPT


def _format_docs(docs: List[Document]) -> str:
    """Join retrieved documents into a single context string."""
    return "\n\n---\n\n".join(
        f"[Source: {d.metadata.get('source', 'unknown')}]\n{d.page_content}"
        for d in docs
    )


def _get_llm():
    return ChatOpenAI(
        base_url=OPENROUTER_BASE_URL,
        api_key=OPENROUTER_API_KEY,
        model=OPENROUTER_MODEL,
        temperature=LLM_TEMPERATURE,
        max_tokens=LLM_MAX_TOKENS,
    )


def _get_prompt():
    return ChatPromptTemplate.from_messages([
        ("system", SYSTEM_PROMPT),
        ("human", USER_PROMPT),
    ])


def build_chain(retriever: BaseRetriever):
    """Build the SECURED RAG chain with Context Guard."""
    chain = (
        {
            "context": retriever | RunnableLambda(sanitize_context) | _format_docs,
            "question": RunnablePassthrough(),
        }
        | _get_prompt()
        | _get_llm()
        | StrOutputParser()
    )
    return chain


def build_raw_chain(retriever: BaseRetriever):
    """Build the RAW RAG chain WITHOUT Context Guard (for demo comparison)."""
    chain = (
        {
            "context": retriever | _format_docs,
            "question": RunnablePassthrough(),
        }
        | _get_prompt()
        | _get_llm()
        | StrOutputParser()
    )
    return chain


def invoke_with_context(
    retriever: BaseRetriever,
    query: str,
    apply_guard: bool = True,
) -> Dict:
    """Invoke the RAG pipeline with full context visibility.

    Returns a dict with:
        response: str — LLM response
        raw_context: str — what the retriever fetched (before guard)
        sanitized_context: str — what the LLM saw (after guard, if applied)
        context_guard_applied: bool
        context_guard_categories: list[str] — categories that were redacted
    """
    # Step 1: Retrieve
    raw_docs = retriever.invoke(query)

    # Step 2: Optionally sanitize
    if apply_guard:
        sanitized_docs = sanitize_context(raw_docs)
        redacted_categories = get_redacted_categories(raw_docs, sanitized_docs)
    else:
        sanitized_docs = raw_docs
        redacted_categories = []

    # Step 3: Format context
    raw_context = _format_docs(raw_docs)
    sanitized_context = _format_docs(sanitized_docs)

    # Step 4: Call LLM with sanitized context
    prompt = _get_prompt()
    llm = _get_llm()
    parser = StrOutputParser()

    chain = prompt | llm | parser
    response = chain.invoke({"context": sanitized_context, "question": query})

    return {
        "response": str(response),
        "raw_context": raw_context,
        "sanitized_context": sanitized_context,
        "context_guard_applied": apply_guard,
        "context_guard_categories": redacted_categories,
    }
