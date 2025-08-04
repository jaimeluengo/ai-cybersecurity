import os
import json
import requests
from typing import List, Set, Dict, Any, TypedDict

# Core LangChain imports for building the agent
from langchain_core.runnables import Runnable
from langchain.agents import AgentExecutor
from langchain.agents.format_scratchpad.tools import format_to_tool_messages
from langchain.agents.output_parsers.tools import ToolsAgentOutputParser
from langchain.tools.render import format_tool_to_openai_function

# Core message and prompt imports
from langchain_core.messages import HumanMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder

# The specific LLM and tools
# ** THE FIX IS HERE: Import ChatVertexAI instead of VertexAI **
from langchain_google_vertexai import ChatVertexAI
from langchain.tools import tool

# The graph and state management
from langgraph.graph import StateGraph, END

# --- 1. DEFINE THE TOOLS (No changes here) ---


def _vt_request(endpoint: str, api_key: str):
    """Helper function to make requests to the VirusTotal API."""
    if not api_key:
        return {"error": "VirusTotal API key not set."}
    url = f"https://www.virustotal.com/api/v3/{endpoint}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as e:
        return {
            "error": f"HTTP Error: {e.response.status_code}",
            "details": e.response.text,
        }


@tool
def get_contacted_domains(file_hash: str) -> dict:
    """Finds domains contacted by a specific file (malware)."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    return _vt_request(f"files/{file_hash}/contacted_domains", api_key)


@tool
def get_contacted_ips(file_hash: str) -> dict:
    """Finds IP addresses contacted by a specific file (malware)."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    return _vt_request(f"files/{file_hash}/contacted_ips", api_key)


@tool
def get_ip_resolutions(domain: str) -> dict:
    """Finds IP addresses that a domain has resolved to."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    return _vt_request(f"domains/{domain}/resolutions", api_key)


@tool
def get_files_downloaded_from_ip(ip_address: str) -> dict:
    """Finds files that have been downloaded from a specific IP address."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    return _vt_request(f"ip_addresses/{ip_address}/files_downloaded_from", api_key)


# --- 2. DEFINE THE STATE OF OUR GRAPH (No changes here) ---


class GraphState(TypedDict):
    initial_indicator: str
    max_depth: int
    current_depth: int
    indicators_to_visit: List[Dict[str, str]]
    visited_indicators: Set[str]
    infrastructure_map: List[Dict[str, Any]]
    final_summary: str
    pivoting_agent: Runnable
    correlator_agent: Runnable


# --- 3. DEFINE THE AGENTS AND NODES (No changes here, logic is sound) ---


def create_agent(llm: ChatVertexAI, tools: list, system_prompt: str):
    """Factory function to create a new agent executor using a robust, compatible method."""
    functions = [format_tool_to_openai_function(t) for t in tools]
    llm_with_tools = llm.bind(functions=functions)

    prompt = ChatPromptTemplate.from_messages(
        [
            ("system", system_prompt),
            MessagesPlaceholder(variable_name="messages"),
            MessagesPlaceholder(variable_name="agent_scratchpad"),
        ]
    )

    agent_runnable = (
        {
            "messages": lambda x: x["messages"],
            "agent_scratchpad": lambda x: format_to_tool_messages(
                x["intermediate_steps"]
            ),
        }
        | prompt
        | llm_with_tools
        | ToolsAgentOutputParser()
    )

    return AgentExecutor(
        agent=agent_runnable, tools=tools, handle_parsing_errors=True, verbose=True
    )


def exploration_node(state: GraphState) -> GraphState:
    """The node that runs the PivotingAgent to explore new indicators."""
    print(f"\n--- EXPLORATION (Depth: {state['current_depth']}) ---")

    if not state["indicators_to_visit"]:
        return state

    indicator_data = state["indicators_to_visit"].pop(0)
    indicator_value = indicator_data["value"]
    indicator_type = indicator_data["type"]

    if indicator_value in state["visited_indicators"]:
        print(f"[*] Skipping already visited indicator: {indicator_value}")
        return state

    print(f"[*] Exploring indicator: {indicator_value} (Type: {indicator_type})")
    state["visited_indicators"].add(indicator_value)

    pivoting_agent = state["pivoting_agent"]
    prompt_text = f"Investigate the '{indicator_type}' indicator: {indicator_value}. Use your tools to find all directly related IPs, domains, or files."

    result = pivoting_agent.invoke({"messages": [HumanMessage(content=prompt_text)]})

    state["infrastructure_map"].append(
        {"source": indicator_value, "result": result["output"]}
    )

    state["current_depth"] += 1
    return state


def summarization_node(state: GraphState) -> GraphState:
    """The node that runs the CorrelatorAgent to generate the final report."""
    print("\n--- SUMMARIZATION ---")
    print("[*] All exploration complete. Generating final report...")

    correlator_agent = state["correlator_agent"]
    map_as_string = json.dumps(state["infrastructure_map"], indent=2)
    prompt_text = f"Analyze the following threat infrastructure map, which was built by recursively exploring relationships in VirusTotal. Identify key hubs, summarize the campaign's likely purpose, and provide a report.\n\n{map_as_string}"

    result = correlator_agent.invoke({"messages": [HumanMessage(content=prompt_text)]})
    state["final_summary"] = result["output"]
    return state


# --- 4. DEFINE THE ROUTING LOGIC (No changes here) ---


def should_continue(state: GraphState) -> str:
    """The router that decides whether to continue exploring or end."""
    print("--- ROUTING ---")
    if state["current_depth"] >= state["max_depth"] or not state["indicators_to_visit"]:
        print("[*] Decision: Exploration limit reached. Proceeding to summarization.")
        return "end"
    else:
        print("[*] Decision: More indicators to visit. Continuing exploration.")
        return "continue"


# --- 5. ASSEMBLE AND RUN THE GRAPH ---

if __name__ == "__main__":
    if not all([os.getenv("VIRUSTOTAL_API_KEY"), os.getenv("GCP_PROJECT_ID")]):
        print(
            "\n[!] ERROR: Please set VIRUSTOTAL_API_KEY and GCP_PROJECT_ID environment variables."
        )
    else:
        print("--- Initializing Agents and Graph ---")

        # ** THE FIX IS HERE: Use ChatVertexAI **
        llm = ChatVertexAI(
            project=os.getenv("GCP_PROJECT_ID"),
            model_name="gemini-2.5-pro",
            temperature=0.0,
            convert_system_message_to_human=True,  # Important for Gemini compatibility
        )

        # Initialize the Pivoting Agent
        pivoting_tools = [
            get_contacted_domains,
            get_contacted_ips,
            get_ip_resolutions,
            get_files_downloaded_from_ip,
        ]
        pivoting_agent_executor = create_agent(
            llm,
            pivoting_tools,
            "You are a threat intelligence 'Pivoting Bot'. Your only job is to take a single indicator (like a file hash, domain, or IP) and use your tools to find all directly connected indicators. Do not analyze or summarize, just return the raw findings from your tools.",
        )

        # Initialize the Correlator Agent (it has no tools)
        correlator_agent_executor = create_agent(
            llm,
            [],
            "You are a senior threat intelligence analyst. You will be given a JSON object representing a map of a threat actor's infrastructure. Your task is to analyze the connections, identify central hubs, describe the campaign's function, and write a summary report.",
        )

        # Define the graph
        workflow = StateGraph(GraphState)
        workflow.add_node("explore", exploration_node)
        workflow.add_node("summarize", summarization_node)
        workflow.add_conditional_edges(
            "explore", should_continue, {"continue": "explore", "end": "summarize"}
        )
        workflow.add_edge("summarize", END)
        workflow.set_entry_point("explore")

        app = workflow.compile()

        # Set Initial State and Run
        STARTING_HASH = (
            "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
        )

        initial_state = {
            "initial_indicator": STARTING_HASH,
            "max_depth": 2,
            "current_depth": 0,
            "indicators_to_visit": [{"type": "file", "value": STARTING_HASH}],
            "visited_indicators": set(),
            "infrastructure_map": [],
            "final_summary": "",
            "pivoting_agent": pivoting_agent_executor,
            "correlator_agent": correlator_agent_executor,
        }

        print(f"\n--- Starting Threat Campaign Mapping for: {STARTING_HASH} ---")
        final_state = app.invoke(initial_state, {"recursion_limit": 15})

        print("\n" + "=" * 50)
        print("          FINAL THREAT INFRASTRUCTURE REPORT")
        print("=" * 50 + "\n")
        print(final_state.get("final_summary", "No summary was generated."))
