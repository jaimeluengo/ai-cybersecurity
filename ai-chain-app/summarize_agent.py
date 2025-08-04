import json
import streamlit as st
from langchain_google_vertexai import VertexAI
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
from google.cloud.aiplatform_v1.types import HarmCategory, SafetySetting
from google.auth.exceptions import DefaultCredentialsError

def summarize_report_with_vertexai(gcp_project_id: str, vt_report: dict, report_date: str):
    """
    Summarizes a VirusTotal report using Vertex AI Gemini.
    """
    st.info("Preparing summary with Vertex AI Gemini...")

    attributes = vt_report.get("data", {}).get("attributes", {})
    relevant_data = {
        "last_analysis_stats": attributes.get("last_analysis_stats"),
        "last_analysis_results": {
            k: v for k, v in attributes.get("last_analysis_results", {}).items()
            if v.get("category") == "malicious"
        },
        "names": attributes.get("names"),
        "meaningful_name": attributes.get("meaningful_name"),
        "type_description": attributes.get("type_description"),
        "tags": attributes.get("tags"),
        "total_votes": attributes.get("total_votes"),
    }
    vt_json_string = json.dumps(relevant_data, indent=2)

    # Malware reports can contain strings that trigger safety filters.
    # For this trusted, internal use case, we disable them to ensure a
    # complete summary is returned.
    safety_settings = {
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: SafetySetting.HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_HARASSMENT: SafetySetting.HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: SafetySetting.HarmBlockThreshold.BLOCK_NONE,
        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: SafetySetting.HarmBlockThreshold.BLOCK_NONE,
    }
    try:
        llm = VertexAI(
            project=gcp_project_id, model_name="gemini-2.5-pro", temperature=0.1,
            max_output_tokens=2048, safety_settings=safety_settings
        )
    except Exception as e:
        st.error(f"Failed to initialize Vertex AI LLM: {e}")
        return None

    prompt_template_text = """**Threat Intelligence Report**
Date: {report_date}
Analyst: Senior Cybersecurity Threat Analyst (AI-Generated)
Confidence: High

---

You are a senior cybersecurity threat analyst. Your task is to provide a clear, concise, and actionable threat intelligence summary based on the provided VirusTotal JSON data for a file.

Analyze the following VirusTotal JSON report:
```json
{vt_json}```

Based on the data, provide the following in your summary using Markdown formatting:
1.  **Executive Summary:** A brief, high-level overview of the threat. Is it malware? What type? What is the risk level?
2.  **Key Detections:** List the most common and significant malware family names identified by the AV engines (e.g., "WannaCry", "Emotet", "Upatre").
3.  **Threat Actor / Malware Family:** If possible, associate the file with a known threat actor or malware family based on the detection names and tags.
4.  **Recommendation:** Provide a clear, actionable recommendation for a security team (e.g., "Block this hash immediately," "Isolate affected hosts," "This appears to be a false positive, no action needed.")."""

    prompt = PromptTemplate(template=prompt_template_text, input_variables=["vt_json", "report_date"])
    summary_chain = prompt | llm | StrOutputParser()

    try:
        with st.spinner("Generating AI Summary... This may take a moment."):
            summary = summary_chain.invoke({"vt_json": vt_json_string, "report_date": report_date})

        if not summary or not summary.strip():
            st.warning("The AI model returned an empty summary...")
            return "Error: AI model returned an empty response."
        else:
            st.success("Successfully generated summary!")
            return summary
    except Exception as e:
        st.error(f"An error occurred while generating the summary: {e}")
        return None