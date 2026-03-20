"""Load and chunk markdown + JSON documents from the knowledge base."""

import json
import os
from typing import List

from langchain_core.documents import Document
from langchain_text_splitters import (
    MarkdownHeaderTextSplitter,
    RecursiveCharacterTextSplitter,
)

from ai_security_wrapper.agent.rag.config import (
    CHUNK_OVERLAP,
    CHUNK_SIZE,
    DOCUMENTS_DIR,
)

# Markdown header levels to split on
_MD_HEADERS = [
    ("#", "h1"),
    ("##", "h2"),
    ("###", "h3"),
]


def _load_markdown_files() -> List[Document]:
    """Walk documents/ and load all .md files with header-aware chunking."""
    md_splitter = MarkdownHeaderTextSplitter(
        headers_to_split_on=_MD_HEADERS,
        strip_headers=False,
    )
    char_splitter = RecursiveCharacterTextSplitter(
        chunk_size=CHUNK_SIZE,
        chunk_overlap=CHUNK_OVERLAP,
    )

    docs = []
    for root, _, files in os.walk(DOCUMENTS_DIR):
        for fname in sorted(files):
            if not fname.endswith(".md"):
                continue

            fpath = os.path.join(root, fname)
            rel_path = os.path.relpath(fpath, DOCUMENTS_DIR).replace("\\", "/")
            category = rel_path.split("/")[0] if "/" in rel_path else "general"

            with open(fpath, encoding="utf-8") as f:
                content = f.read()

            # Split by markdown headers first
            header_chunks = md_splitter.split_text(content)

            # Secondary split for oversized chunks
            chunk_counter = 0
            for hc in header_chunks:
                sub_chunks = char_splitter.split_text(hc.page_content)
                for _idx, text in enumerate(sub_chunks):
                    header = hc.metadata.get("h3") or hc.metadata.get("h2") or hc.metadata.get("h1") or fname
                    doc_id = f"{rel_path}::{chunk_counter}"
                    chunk_counter += 1
                    docs.append(Document(
                        page_content=text,
                        metadata={
                            "doc_id": doc_id,
                            "source": rel_path,
                            "category": category,
                            "header": header,
                        },
                    ))

    return docs


def _load_json_users() -> List[Document]:
    """Load users.json and convert each record to a human-readable Document."""
    json_path = os.path.join(DOCUMENTS_DIR, "user", "users.json")
    if not os.path.exists(json_path):
        return []

    with open(json_path, encoding="utf-8") as f:
        users = json.load(f)

    docs = []
    for user in users:
        uid = user.get("user_id", "unknown")
        name = user.get("name", "Unknown")
        text = (
            f"User Profile - {name} ({uid})\n"
            f"Email: {user.get('email', 'N/A')} | Phone: {user.get('phone', 'N/A')}\n"
            f"KYC Status: {user.get('kyc_status', 'N/A')} | "
            f"Risk Score: {user.get('risk_score', 'N/A')} | "
            f"Balance: {user.get('balance', 'N/A')} {user.get('currency', '')}\n"
            f"Account Status: {user.get('status', 'N/A')} | "
            f"Country: {user.get('country', 'N/A')} | "
            f"Created: {user.get('created_at', 'N/A')}"
        )
        docs.append(Document(
            page_content=text,
            metadata={
                "doc_id": f"user/users.json::{uid}",
                "source": "user/users.json",
                "category": "user_data",
                "user_id": uid,
            },
        ))

    return docs


def load_all_documents() -> List[Document]:
    """Load and chunk all documents from the knowledge base."""
    md_docs = _load_markdown_files()
    user_docs = _load_json_users()
    return md_docs + user_docs
