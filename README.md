# 🕵️ AI Cybersecurity Agent Evolution

This repository showcases the evolution of an AI-powered cybersecurity analysis tool, demonstrating a progression from a simple summarization chain to a complex, multi-agent system. Each application builds upon the last, offering a practical look at how to increase the autonomy and capability of AI agents using LangChain and Google Vertex AI.

## Project Structure

This repository is organized into several applications, each representing a different level of complexity.

- **`/local`**: Contains command-line versions of the applications. These are useful for quick, headless testing and understanding the core logic without a UI.

- **`/ai-chain-app` (Level 1: Simple Summarizer)**: A basic Streamlit application that uses a simple LangChain "chain". It takes a raw VirusTotal JSON report and feeds it to an LLM with a prompt to generate a human-readable summary. This represents the most basic form of LLM integration.

- **`/ai-agent-app` (Level 2: ReAct Agent)**: An evolution of the first app, this introduces a single, autonomous agent built with the ReAct (Reasoning and Acting) framework. The agent can use tools like VirusTotal and web search to actively investigate a threat, showing its thought process in real-time.

- **`/multi-agent-app` (Level 3: Multi-Agent Mapper)**: The most advanced implementation, this application uses LangGraph to orchestrate a team of specialized AI agents. A "Pivoting" agent explores threat infrastructure, and a "Correlator" agent analyzes the findings to produce a comprehensive map and report on a potential threat campaign.

---

## Tech Stack

- **Framework:** Streamlit
- **AI/LLM Orchestration:** LangChain
- **Multi-Agent Orchestration:** LangGraph
- **LLM Provider:** Google Vertex AI (Gemini 2.5 Pro)
- **Tools:** VirusTotal API, SerpAPI
- **Containerization:** Docker
- **Deployment:** Google Cloud Run

---

## Getting Started

Follow these instructions to get a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- Python 3.10+
- Google Cloud SDK installed and authenticated.
- Access to a Google Cloud Project with the Vertex AI API enabled.

### 1. Clone the Repository

```bash
git clone https://github.com/jaimeluengo/ai-cybersecurity.git
cd ai-cybersecurity
```

### 2. Set Up a Virtual Environment

It's highly recommended to use a virtual environment to manage dependencies.

```bash
python -m venv venv
source venv/bin/activate
# On Windows, use: venv\Scripts\activate
```

### 3. Install Dependencies

Navigate into the directory of the app you want to run (e.g., `cd multi-agent-app`) and install its dependencies.

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Each application requires API keys to function. Create a `.env` file inside the specific app's directory (e.g., `multi-agent-app/.env`) and add your keys:

```
# .env
VIRUSTOTAL_API_KEY="your_virustotal_api_key_here"
GCP_PROJECT_ID="your-gcp-project-id-here"
SERPAPI_API_KEY="your_serpapi_api_key_here"
```

You will also need to authenticate your local environment with Google Cloud:

```bash
gcloud auth application-default login
```

### 5. Run an Application Locally

From within an application's directory (e.g., `multi-agent-app`), run the Streamlit app:

```bash
streamlit run app.py
```

Open your web browser and navigate to `http://localhost:8501`.

---

## Deployment to Google Cloud Run

Each application is designed to be deployed as a container on Google Cloud Run. The following example shows how to deploy the `multi-agent-app`.

1.  **Build the container image using Cloud Build:**
    _(Run this command from within the `multi-agent-app` directory)_

    ```bash
    gcloud builds submit --tag gcr.io/[YOUR_GCP_PROJECT_ID]/multi-agent-threat-mapper .
    ```

2.  **Deploy the image to Cloud Run:**

    **Note on Security:** For a production environment, it is **strongly recommended** to use Google Secret Manager for your API keys instead of setting them as plain-text environment variables. The command below is for quick testing.

    ```bash
    gcloud run deploy multi-agent-threat-mapper \
      --image gcr.io/[YOUR_GCP_PROJECT_ID]/multi-agent-threat-mapper \
      --platform managed \
      --region us-central1 \
      --allow-unauthenticated \
      --set-env-vars "VIRUSTOTAL_API_KEY=[YOUR_VT_KEY],SERPAPI_API_KEY=[YOUR_SERPAPI_KEY],GCP_PROJECT_ID=[YOUR_GCP_PROJECT_ID]"
    ```
