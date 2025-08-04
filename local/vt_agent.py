import requests
import os
import json
from langchain_google_vertexai import VertexAI
from langchain.agents import AgentExecutor, create_react_agent
from langchain.tools import tool
from langchain_core.prompts import PromptTemplate
from langchain_community.utilities import SerpAPIWrapper

# --- Tool 1: Get VirusTotal File Report ---
@tool
def get_virustotal_file_report(file_hash: str) -> str:
    """
    Retrieves the file analysis report from the VirusTotal API for a given MD5, SHA1 or SHA256 hash. Use this to get initial data on a suspicious file. Returns a JSON string of the report.
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
        
        # Prune the report to only the most essential details to save tokens
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

# --- Tool 2: A REAL Web Search Tool ---
@tool
def web_search_for_threat(query: str) -> str:
    """
    Performs a web search using the SerpAPI to find information on cybersecurity threats, malware families, or threat actors. Use this when you need more context on a name (like a tag or threat name) found in a report.
    """
    if not os.getenv("SERPAPI_API_KEY"):
        return "Error: SERPAPI_API_KEY environment variable is not set."
    
    search = SerpAPIWrapper()
    return search.run(query)


# --- Main Agent Logic ---
if __name__ == "__main__":
    # --- Configuration ---
    VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
    GCP_PROJECT_ID = os.getenv("GCP_PROJECT_ID")
    SERPAPI_API_KEY = os.getenv("SERPAPI_API_KEY") # Needed for a real search tool

    if not all([VT_API_KEY, GCP_PROJECT_ID]):
        print("[!] ERROR: Set VIRUSTOTAL_API_KEY and GCP_PROJECT_ID env vars.")
    else:
        # Define the tools the agent can use
        tools = [
            get_virustotal_file_report,
            web_search_for_threat,
        ]

        # Define the core agent prompt. This is crucial.
        # It tells the agent HOW to reason.
        prompt = PromptTemplate.from_template("""
        You are a powerful AI assistant for cybersecurity analysis. Answer the user's request by using the tools provided.

        You have access to the following tools:
        {tools}

        Use the following format for your thought process (the ReAct framework):

        Thought: Your internal reasoning on what to do next. You must always think about what to do next.
        Action: The tool you will use. Must be one of [{tool_names}].
        Action Input: The input to that tool.
        Observation: The result from the tool.
        ... (this Thought/Action/Action Input/Observation cycle can repeat multiple times) ...
        Thought: I now have enough information to answer the user's request.
        Final Answer: The final, comprehensive answer to the user, summarized in a clear Markdown format. Provide a risk assessment and a clear recommendation.

        Begin!

        User Request: {input}
        Thought: {agent_scratchpad}
        """)

        # Initialize the LLM. Using a more advanced model for better agent reasoning.
        llm = VertexAI(project=GCP_PROJECT_ID, model_name="gemini-2.5-pro", temperature=0.0)

        # Create the agent itself
        agent = create_react_agent(llm, tools, prompt)

        # Create the agent executor, which runs the agent's reasoning loop
        agent_executor = AgentExecutor(agent=agent, tools=tools, verbose=True)

        # --- Invoke the Agent ---
        # The agent will now decide which tools to call on its own.
        user_query = "Please investigate the file hash ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa and tell me what it is and how dangerous it is."
        
        try:
            result = agent_executor.invoke({"input": user_query})
            print("\n" + "---" * 20)
            print("      Final Agent Response")
            print("---" * 20 + "\n")
            print(result['output'])
        except Exception as e:
            print(f"An error occurred during agent execution: {e}")