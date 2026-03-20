"""UI 1 — Raw RAG Chatbot (No Security Layers)
Directly calls the RAG chain, bypassing all security.
Shows retrieved context alongside the chat to demonstrate what the LLM sees.
Run: streamlit run ui/raw_chatbot.py --server.port 8501
"""

import sys
import os

# Ensure project root is on sys.path for imports
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import streamlit as st
from ui.common.styles import inject_raw_styles
from ui.common.attack_prompts import ATTACK_PROMPTS

st.set_page_config(
    page_title="FinNova RAG - RAW (No Security)",
    page_icon="\U0001F513",
    layout="wide",
)

inject_raw_styles()


def _escape_html(text: str) -> str:
    """Escape HTML special characters for safe display."""
    return (
        text.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("\n", "<br>")
    )


# ── RAG components (cached across reruns) ─────────────────────────────────────
@st.cache_resource
def load_components():
    from ai_security_wrapper.agent.rag.indexer import get_raw_chain, get_retriever
    return get_raw_chain(), get_retriever()


# ── Session state init ───────────────────────────────────────────────────────
if "messages" not in st.session_state:
    st.session_state.messages = []

if "pending_input" not in st.session_state:
    st.session_state.pending_input = None

if "last_context" not in st.session_state:
    st.session_state.last_context = None


# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        '<div class="sidebar-warning">'
        "\U0001F6A8 <b>NO SECURITY PROTECTION</b><br>"
        "This chatbot returns raw LLM output with no filtering, "
        "no auth, and no prompt injection detection."
        "</div>",
        unsafe_allow_html=True,
    )

    if st.button("\U0001F5D1 Clear Chat", use_container_width=True):
        st.session_state.messages = []
        st.session_state.pending_input = None
        st.session_state.last_context = None
        st.rerun()

    st.markdown("---")
    st.markdown("### \U0001F9EA Test Prompts")

    for category, prompts in ATTACK_PROMPTS.items():
        with st.expander(category):
            for prompt in prompts:
                if st.button(prompt, key=f"raw_{hash(prompt)}"):
                    st.session_state.pending_input = prompt
                    st.rerun()


# ── Header ───────────────────────────────────────────────────────────────────
st.markdown(
    '<div class="banner-raw">'
    "\U0001F513 RAW RAG Chatbot &mdash; NO SECURITY LAYERS"
    "</div>",
    unsafe_allow_html=True,
)
st.caption("Direct access to the RAG chain. No auth, no input sanitizer, no output filter, no audit logging.")


# ── Two-column layout: Chat + Context ────────────────────────────────────────
chat_col, context_col = st.columns([3, 2])


# ── Chat column ──────────────────────────────────────────────────────────────
with chat_col:
    # Chat history
    for msg in st.session_state.messages:
        with st.chat_message(msg["role"]):
            st.markdown(msg["content"])
            if msg["role"] == "assistant":
                st.markdown(
                    '<span class="badge-warning">\u26A0 No security filters applied</span>',
                    unsafe_allow_html=True,
                )

    # Handle pending input from sidebar buttons
    user_input = st.chat_input("Ask anything...")

    if st.session_state.pending_input:
        user_input = st.session_state.pending_input
        st.session_state.pending_input = None

    # Process input
    if user_input:
        st.session_state.messages.append({"role": "user", "content": user_input})
        with st.chat_message("user"):
            st.markdown(user_input)

        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                try:
                    chain, retriever = load_components()

                    # Step 1: Retrieve context (for display)
                    raw_docs = retriever.invoke(user_input)
                    context_chunks = []
                    for doc in raw_docs:
                        context_chunks.append({
                            "source": doc.metadata.get("source", "unknown"),
                            "category": doc.metadata.get("category", "unknown"),
                            "content": doc.page_content,
                        })
                    st.session_state.last_context = context_chunks

                    # Step 2: Get LLM response (raw chain, no guard)
                    response = chain.invoke(user_input)
                except Exception as e:
                    response = f"Error: {e}"
                    st.session_state.last_context = None

            st.markdown(response)
            st.markdown(
                '<span class="badge-warning">\u26A0 No security filters applied</span>',
                unsafe_allow_html=True,
            )

        st.session_state.messages.append({"role": "assistant", "content": response})


# ── Context panel ────────────────────────────────────────────────────────────
with context_col:
    st.markdown("### \U0001F4E6 Retrieved Context (What LLM Sees)")
    st.caption("These are the raw document chunks retrieved from the vector database. "
               "The LLM receives ALL of this data in its context window — with zero redaction.")

    if st.session_state.last_context:
        for i, chunk in enumerate(st.session_state.last_context):
            with st.expander(
                f"Chunk {i+1} — {chunk['source']} [{chunk['category']}]",
                expanded=(i < 3),
            ):
                st.markdown(
                    f'<div class="context-chunk">'
                    f'<div class="context-chunk-source">'
                    f"Source: {chunk['source']} | Category: {chunk['category']}"
                    f'</div>'
                    f"{_escape_html(chunk['content'])}"
                    f'</div>',
                    unsafe_allow_html=True,
                )
    else:
        st.info("Send a message to see what chunks the retriever fetches.")
