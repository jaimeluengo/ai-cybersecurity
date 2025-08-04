import streamlit as st
import os
from datetime import datetime # <-- IMPORT DATETIME

# Import your custom functions
from vt_query import get_virustotal_report
from summarize_agent import summarize_report_with_vertexai

# ... (Page config and styling are the same)
st.set_page_config(page_title="AI-Powered Threat Intelligence", page_icon="🤖", layout="wide")
# ...

# --- Secrets and Configuration ---
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")

# --- UI Layout ---
st.title("🤖 AI-Powered Threat Intelligence Summarizer")
st.markdown("Enter a file hash (MD5, SHA-1, or SHA-256) to get a comprehensive, AI-generated threat report from VirusTotal and Vertex AI.")

# --- Main Application Logic ---
if not VT_API_KEY or not GCP_PROJECT_ID:
    st.error("FATAL ERROR: Application is missing required environment variables...")
else:
    example_hash = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
    st.info(f"Example hash (WannaCry): `{example_hash}`", icon="💡")

    file_hash = st.text_input("Enter File Hash:", "", placeholder="e.g., ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")

    if st.button("Analyze Hash", type="primary"):
        if file_hash:
            vt_report = get_virustotal_report(VT_API_KEY, file_hash.strip())

            if vt_report:
                # MODIFICATION: Get the current date and pass it to the function
                current_date = datetime.now().strftime("%Y-%m-%d")
                summary = summarize_report_with_vertexai(GCP_PROJECT_ID, vt_report, current_date)

                if summary:
                    st.subheader("AI-Generated Summary")
                    st.markdown(summary)
                    with st.expander("Show Raw VirusTotal JSON Data"):
                        st.json(vt_report)
        else:
            st.warning("Please enter a file hash to analyze.")