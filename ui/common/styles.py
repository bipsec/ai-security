"""Shared CSS themes and helpers for raw vs secured chatbot UIs."""

import streamlit as st

RAW_BANNER_CSS = """
<style>
.banner-raw {
    background: linear-gradient(90deg, #dc3545, #c82333);
    color: white;
    padding: 12px 20px;
    border-radius: 8px;
    text-align: center;
    font-size: 1.3em;
    font-weight: bold;
    margin-bottom: 16px;
}
.badge-warning {
    background: #fff3cd;
    color: #856404;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.85em;
    display: inline-block;
    margin-top: 4px;
}
.sidebar-warning {
    background: #f8d7da;
    border: 1px solid #f5c6cb;
    color: #721c24;
    padding: 12px;
    border-radius: 8px;
    margin-bottom: 12px;
}
.context-panel {
    background: #1e1e1e;
    color: #d4d4d4;
    padding: 12px;
    border-radius: 8px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 0.82em;
    line-height: 1.5;
    max-height: 500px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
}
.context-chunk {
    border-left: 3px solid #dc3545;
    padding: 8px 12px;
    margin: 8px 0;
    background: #2d2d2d;
    border-radius: 0 4px 4px 0;
}
.context-chunk-source {
    color: #6c757d;
    font-size: 0.8em;
    margin-bottom: 4px;
}
.sensitive-highlight {
    background: rgba(220, 53, 69, 0.3);
    padding: 1px 3px;
    border-radius: 2px;
    color: #ff6b6b;
}
</style>
"""

SECURED_BANNER_CSS = """
<style>
.banner-secured {
    background: linear-gradient(90deg, #28a745, #218838);
    color: white;
    padding: 12px 20px;
    border-radius: 8px;
    text-align: center;
    font-size: 1.3em;
    font-weight: bold;
    margin-bottom: 16px;
}
.badge-blocked {
    background: #f8d7da;
    color: #721c24;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.85em;
    font-weight: bold;
    display: inline-block;
}
.badge-redacted {
    background: #fff3cd;
    color: #856404;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.85em;
    font-weight: bold;
    display: inline-block;
}
.badge-passed {
    background: #d4edda;
    color: #155724;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.85em;
    font-weight: bold;
    display: inline-block;
}
.badge-guard {
    background: #cce5ff;
    color: #004085;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.85em;
    font-weight: bold;
    display: inline-block;
}
.badge-quality-grounded {
    background: #d4edda;
    color: #155724;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.85em;
    font-weight: bold;
    display: inline-block;
}
.badge-quality-redirected {
    background: #cce5ff;
    color: #004085;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.85em;
    font-weight: bold;
    display: inline-block;
}
.sidebar-success {
    background: #d4edda;
    border: 1px solid #c3e6cb;
    color: #155724;
    padding: 12px;
    border-radius: 8px;
    margin-bottom: 12px;
}
.security-report {
    background: #f8f9fa;
    border: 1px solid #dee2e6;
    padding: 12px;
    border-radius: 8px;
    font-size: 0.9em;
    margin-top: 8px;
}
.context-diff-raw {
    background: #2d1515;
    color: #ff8888;
    padding: 10px;
    border-radius: 6px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 0.8em;
    line-height: 1.4;
    max-height: 300px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
    border-left: 3px solid #dc3545;
}
.context-diff-sanitized {
    background: #152d15;
    color: #88ff88;
    padding: 10px;
    border-radius: 6px;
    font-family: 'Consolas', 'Courier New', monospace;
    font-size: 0.8em;
    line-height: 1.4;
    max-height: 300px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-wrap: break-word;
    border-left: 3px solid #28a745;
}
</style>
"""


def inject_raw_styles():
    st.markdown(RAW_BANNER_CSS, unsafe_allow_html=True)


def inject_secured_styles():
    st.markdown(SECURED_BANNER_CSS, unsafe_allow_html=True)
