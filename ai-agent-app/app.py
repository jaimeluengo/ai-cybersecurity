import streamlit as st
import os
import json
import requests

from langchain_google_vertexai import VertexAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import tool
from langchain_core.prompts import PromptTemplate
from langchain_community.utilities import SerpAPIWrapper

# --- Page Configuration and Styling ---
st.set_page_config(
    page_title="Cybersecurity Analysis Agent", page_icon="🕵️", layout="wide"
)

st.markdown(
    """
<style>
    .reportview-container { background: #f0f2f6; }
    .st-emotion-cache-16txtl3 { padding: 2rem 2rem 2rem; }
    h1 { color: #C2410C; }
    .thought-bubble {
        background-color: #E0E7FF;
        border-left: 5px solid #4F46E5;
        padding: 0.5rem 1rem;
        margin-bottom: 1rem;
        border-radius: 5px;
    }
</style>
""",
    unsafe_allow_html=True,
)


@tool
def get_virustotal_file_report(file_hash: str) -> str:
    """
    Retrieves the file analysis report from the VirusTotal API for a given MD5,
    SHA1 or SHA256 hash. Use this to get initial data on a suspicious file.
    Returns a JSON string of the report.
    """
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return "Error: VIRUSTOTAL_API_KEY environment variable is not set."

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        report = response.json()
        attributes = report.get("data", {}).get("attributes", {})
        essential_data = {
            "last_analysis_stats": attributes.get("last_analysis_stats"),
            "meaningful_name": attributes.get("meaningful_name"),
            "reputation": attributes.get("reputation"),
            "tags": attributes.get("tags"),
            "total_votes": attributes.get("total_votes"),
        }
        return json.dumps(essential_data, indent=2)
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return f"Error: The file hash '{file_hash}' was not found on VirusTotal."
        return f"HTTP Error from VirusTotal: {e.response.text}"
    except Exception as e:
        return f"An error occurred: {e}"


@tool
def web_search_for_threat(query: str) -> str:
    """
    Performs a web search using the SerpAPI to find information on cybersecurity threats,
    malware families, or threat actors. Use this when you need more context on a name found in a report.
    """
    if not os.getenv("SERPAPI_API_KEY"):
        return "Error: SERPAPI_API_KEY environment variable is not set."
    search = SerpAPIWrapper()
    return search.run(query)


# --- Secrets and Configuration ---
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
SERPAPI_API_KEY = os.getenv("SERPAPI_API_KEY")

# --- UI Layout ---
st.title("🕵️ Cybersecurity Analysis Agent")
st.markdown(
    "Provide a file hash or a question about a threat. The AI agent will autonomously use its tools to investigate and provide a report, showing its thought process in real time."
)

# --- Main Application Logic ---
if not all([VT_API_KEY, GCP_PROJECT_ID, SERPAPI_API_KEY]):
    st.error("FATAL ERROR: One or more required environment variables are missing.")
    st.error(
        "Please ensure VIRUSTOTAL_API_KEY, GCP_PROJECT_ID, and SERPAPI_API_KEY are set."
    )
else:
    example_hash = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
    st.info(f"Example hash (WannaCry): `{example_hash}`", icon="💡")

    user_query = st.text_input(
        "Enter your query for the agent:",
        "",
        placeholder="Investigate hash ed01ebfbc...",
    )

    if st.button("Activate Agent", type="primary"):
        if user_query:
            st.subheader("Agent Mission Log")
            thought_container = st.container()

            try:
                tools = [get_virustotal_file_report, web_search_for_threat]

                # This prompt is specifically structured for a ReAct agent.
                # It needs placeholders for {tools} and {tool_names}.
                prompt = PromptTemplate.from_template(
                    """
                You are a cybersecurity analyst. Your goal is to answer the user's request by using the provided tools to investigate.

                You have access to the following tools:
                {tools}

                Use the following format for your thought process. Your thoughts should be brief and focused on the next step.

                Thought: Your reasoning on what to do next.
                Action: The tool to use, must be one of [{tool_names}].
                Action Input: The input to that tool.
                Observation: The result from the tool.
                ... (this Thought/Action/Action Input/Observation cycle can repeat) ...

                Thought: I now have enough information to answer the user's request.
                Final Answer: [Your final, comprehensive, and well-structured answer in Markdown format. Include a risk assessment and recommendations.]

                Begin!

                User Request: {input}
                Thought: {agent_scratchpad}
                """
                )

                llm = VertexAI(
                    project=GCP_PROJECT_ID, model_name="gemini-2.5-pro", temperature=0.0
                )
                agent = create_react_agent(llm, tools, prompt)
                agent_executor = AgentExecutor(
                    agent=agent,
                    tools=tools,
                    verbose=True,
                    handle_parsing_errors=True,
                    max_iterations=7,
                )

                final_answer = ""
                with st.spinner("Agent is thinking..."):
                    for chunk in agent_executor.stream({"input": user_query}):
                        # Check for agent actions (the thoughts)
                        if "actions" in chunk:
                            for action in chunk["actions"]:
                                thought = (
                                    action.log.strip().split("Thought:")[-1].strip()
                                )
                                thought_container.markdown(f"🤔 **Thought:** {thought}")
                                thought_container.markdown(
                                    f"▶️ **Action:** `{action.tool}` with input `{action.tool_input}`"
                                )

                        # Check for observations from tools
                        elif "steps" in chunk:
                            for step in chunk["steps"]:
                                thought_container.markdown("📋 **Observation:**")
                                # The observation can be a string or a dict, handle both
                                observation_content = step.observation
                                if isinstance(observation_content, dict):
                                    observation_content = json.dumps(
                                        observation_content, indent=2
                                    )
                                thought_container.code(
                                    observation_content, language="json"
                                )
                                thought_container.divider()

                        elif "output" in chunk:
                            final_answer = chunk["output"]

                st.subheader("Final Report")
                st.markdown(final_answer)

            except Exception as e:
                st.error(f"An error occurred during agent execution: {e}")
        else:
            st.warning("Please enter a query for the agent.")
