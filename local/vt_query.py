# /cloud-run-vt-summarizer/vt_query.py

import requests
import streamlit as st

def get_virustotal_report(api_key: str, file_hash: str):
    """
    Retrieves the file analysis report from the VirusTotal API.
    """
    if not api_key:
        st.error("Error: VIRUSTOTAL_API_KEY is not configured.")
        return None

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        with st.spinner(f"Querying VirusTotal for hash: {file_hash}..."):
            response = requests.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
    except requests.exceptions.HTTPError as http_err:
        if http_err.response.status_code == 404:
            st.warning(f"File hash '{file_hash}' was not found in the VirusTotal database.")
        else:
            st.error(f"An HTTP Error occurred: {http_err}")
            st.error(f"Response content: {http_err.response.text}")
    except requests.exceptions.RequestException as req_err:
        st.error(f"A non-HTTP error occurred: {req_err}")

    return None