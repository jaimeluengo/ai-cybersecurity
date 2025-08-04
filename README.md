# 🕵️ AI-Powered Cybersecurity Analysis Agent

This project is a web-based, AI-powered agent designed for cybersecurity analysis. It uses a Large Language Model (LLM) through Google's Vertex AI, combined with LangChain's ReAct agent framework, to autonomously investigate potential threats like file hashes.

The agent is equipped with tools to query the VirusTotal API and perform real-time web searches, allowing it to gather context, form a hypothesis, and deliver a comprehensive report within an interactive Streamlit user interface.

![Screenshot of the application UI](https://via.placeholder.com/800x450.png?text=App+Screenshot+Here)
_(Replace this with a real screenshot of your application)_

## ✨ Features

- **Autonomous Investigation:** The agent can decide which tools to use and in what order to answer a user's query.
- **Interactive UI:** A user-friendly Streamlit interface provides a "mission log" that shows the agent's real-time thought process.
- **Real-Time Web Search:** Uses SerpAPI to gather up-to-the-minute context on malware families, threat actors, and other indicators.
- **VirusTotal Integration:** Directly queries the VirusTotal API for detailed reports on file hashes.
- **Cloud-Native Deployment:** Ready to be deployed as a containerized application on Google Cloud Run.

## 🛠️ Tech Stack

- **Framework:** [Streamlit](https://streamlit.io/)
- **AI/LLM Orchestration:** [LangChain](https://www.langchain.com/)
- **LLM Provider:** [Google Vertex AI](https://cloud.google.com/vertex-ai) (Gemini 2.5 Pro)
- **Tools:** [VirusTotal API](https://www.virustotal.com/), [SerpAPI](https://serpapi.com/)
- **Containerization:** [Docker](https://www.docker.com/)
- **Deployment:** [Google Cloud Run](https://cloud.google.com/run)

---

## 🚀 Getting Started

Follow these instructions to get a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

- Python 3.10+
- [Google Cloud SDK](https://cloud.google.com/sdk/docs/install) installed and authenticated.
- Access to a Google Cloud Project with the Vertex AI API enabled.

### 1. Clone the Repository

```bash
git clone <your-repo-url>
cd virus-total-agent/ai-agent-app
```

### 2. Set Up a Virtual Environment

It's highly recommended to use a virtual environment to manage dependencies.

```bash
python -m venv venv
source venv/bin/activate
# On Windows, use: venv\Scripts\activate
```

### 3. Install Dependencies

Install all the required Python packages.

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

This application requires three API keys to function. Create a `.env` file in the `ai-agent-app` directory and add your keys:

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

### 5. Run the Application Locally

Once the setup is complete, you can run the Streamlit app with the following command:

```bash
streamlit run app.py
```

Open your web browser and navigate to `http://localhost:8501`.

---

## ☁️ Deployment to Google Cloud Run

This application is designed to be deployed as a container on Google Cloud Run.

1.  **Build the container image using Cloud Build:**

    ```bash
    gcloud builds submit --tag gcr.io/your-gcp-project-id-here/vt-agent-app .
    ```

2.  **Deploy the image to Cloud Run:**

    For a production environment, it is **strongly recommended** to use Google Secret Manager for your API keys instead of setting them as plain-text environment variables.

    ```bash
    gcloud run deploy vt-agent-app \
      --image gcr.io/your-gcp-project-id-here/vt-agent-app \
      --platform managed \
      --region us-central1 \
      --allow-unauthenticated \
      --set-env-vars "VIRUSTOTAL_API_KEY=your_key,SERPAPI_API_KEY=your_key,GCP_PROJECT_ID=your_project_id"
    ```

## 📄 License

This project is licensed under the MIT License - see the `LICENSE` file for details.
