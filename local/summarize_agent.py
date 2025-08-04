import os
import json
from langchain_google_vertexai import VertexAI
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import StrOutputParser
# Import the function from the other file to avoid code duplication
from local.vt_query import get_virustotal_report
# Import safety settings components from Google's library
from google.auth.exceptions import DefaultCredentialsError
from google.cloud.aiplatform_v1.types import HarmCategory, SafetySetting


# --- New Function for Step 2 ---
def summarize_report_with_vertexai(summary_chain, vt_report: dict):
    """
    Summarizes a VirusTotal report using a pre-configured LangChain chain.

    Args:
        summary_chain: The pre-configured LangChain chain for summarization.
        vt_report: The raw JSON report from VirusTotal as a dictionary.

    Returns:
        A string containing the AI-generated summary or an error message.
    """
    print("[*] Preparing summary with Vertex AI Gemini...")

    # To improve performance and accuracy, select only the most relevant parts of the report.
    attributes = vt_report.get("data", {}).get("attributes", {})
    relevant_data = {
        "last_analysis_stats": attributes.get("last_analysis_stats"),
        "last_analysis_results": {
            # Filter for only malicious results to reduce noise and token count
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

    try:
        # Invoke the chain with the VirusTotal report
        summary = summary_chain.invoke({"vt_json": vt_json_string})

        # Add a check for an empty response from the LLM
        if not summary or not summary.strip():
            print("[-] Warning: The LLM returned an empty summary. This is likely due to safety filters blocking the response.")
            return "Error: AI model returned an empty response. Check for safety setting blocks in the Google Cloud console."
        else:
            print("[+] Successfully generated summary!")
            return summary
    except Exception as e:
        return f"[-] An error occurred while generating the summary: {e}"


if __name__ == "__main__":
    # --- Configuration ---
    VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
    TEST_HASH = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"

    # --- Validation and Execution ---
    if not all([VT_API_KEY, GCP_PROJECT_ID]):
        print("\n[!] ERROR: Missing required environment variables.")
        print("Please set both VIRUSTOTAL_API_KEY and GCP_PROJECT_ID before running.")
    else:
        # --- Safety Settings Configuration ---
        # Malware reports can contain strings that trigger safety filters.
        # For this trusted, internal use case, we disable them to ensure a
        # complete summary is returned.
        safety_settings = {
            HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: SafetySetting.HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HARASSMENT: SafetySetting.HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_HATE_SPEECH: SafetySetting.HarmBlockThreshold.BLOCK_NONE,
            HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: SafetySetting.HarmBlockThreshold.BLOCK_NONE,
        }

        llm = None
        try:
            # --- LLM Initialization ---
            llm = VertexAI(
                project=GCP_PROJECT_ID,
                model_name="gemini-2.5-pro",
                temperature=0.1,
                max_output_tokens=2048, # Increased for longer summaries
                safety_settings=safety_settings
            )
        except DefaultCredentialsError:
            print("\n[!] AUTHENTICATION ERROR: Google Cloud credentials not found.")
            print("Please authenticate by running the following command in your terminal:")
            print("    gcloud auth application-default login")
            exit(1) # Exit the script as we cannot proceed
        except Exception as e:
            print(f"\n[!] An unexpected error occurred during LLM initialization: {e}")
            exit(1)

        # --- Prompt and Chain Definition ---
        # Define the prompt and chain once for efficiency.
        prompt_template_text = """You are a senior cybersecurity threat analyst. Your task is to provide a clear, concise, and actionable threat intelligence summary based on the provided VirusTotal JSON data for a file.

Analyze the following VirusTotal JSON report:
```json
{vt_json}
```

Based on the data, provide the following in your summary using Markdown formatting:
1.  **Executive Summary:** A brief, high-level overview of the threat. Is it malware? What type? What is the risk level?
2.  **Key Detections:** List the most common and significant malware family names identified by the AV engines (e.g., "WannaCry", "Emotet", "Upatre").
3.  **Threat Actor / Malware Family:** If possible, associate the file with a known threat actor or malware family based on the detection names and tags.
4.  **Recommendation:** Provide a clear, actionable recommendation for a security team (e.g., "Block this hash immediately," "Isolate affected hosts," "This appears to be a false positive, no action needed.")."""

        prompt = PromptTemplate(template=prompt_template_text, input_variables=["vt_json"])
        summary_chain = prompt | llm | StrOutputParser()

        # 1. Get the raw report from VirusTotal
        report = get_virustotal_report(VT_API_KEY, TEST_HASH)

        if report and llm:
            # 2. Pass the report to the summarization agent
            summary = summarize_report_with_vertexai(summary_chain, report)

            # 3. Print the final, user-facing output
            print("\n" + "---" * 20)
            print("      AI-Generated Threat Intelligence Summary")
            print("---" * 20 + "\n")
            print(summary)