import streamlit as st
import os
import json
import requests
from typing import List, Set, Dict, Any, TypedDict

# Core LangChain & LangGraph Imports
from langchain_core.runnables import Runnable
from langchain.agents import AgentExecutor
from langchain.agents.format_scratchpad.tools import format_to_tool_messages
from langchain.agents.output_parsers.tools import ToolsAgentOutputParser
from langchain.tools.render import format_tool_to_openai_function
from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
from langchain_google_vertexai import ChatVertexAI
from langchain.tools import tool
from langchain_community.utilities import SerpAPIWrapper
from langgraph.graph import StateGraph, END
from langchain_core.output_parsers import JsonOutputParser

# --- Page Configuration and Styling ---
st.set_page_config(
    page_title="Multi-Agent Threat Mapper",
    page_icon="🕸️",
    layout="wide"
)

st.markdown("""
<style>
    .reportview-container { background: #f0f2f6; }
    h1 { color: #8A2BE2; } /* BlueViolet for a multi-agent feel */
    .node-box {
        border: 2px solid #ddd;
        border-radius: 10px;
        padding: 1rem;
        margin-bottom: 1rem;
    }
    .node-title {
        font-weight: bold;
        color: #4A5568;
        margin-bottom: 0.5rem;
    }
</style>
""", unsafe_allow_html=True)


# --- 1. DEFINE THE TOOLS ---

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
        return {"error": f"HTTP Error: {e.response.status_code}", "details": e.response.text}

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
def web_search_for_threat(query: str) -> str:
    """Performs a web search to find context on threats, domains, IPs, or hashes."""
    if not os.getenv("SERPAPI_API_KEY"):
        return "Error: SERPAPI_API_KEY environment variable is not set."
    search = SerpAPIWrapper()
    return search.run(query)


# --- 2. DEFINE THE STATE OF OUR GRAPH ---

class GraphState(TypedDict):
    initial_indicator: str
    max_depth: int
    current_depth: int
    indicators_to_visit: List[Dict[str, str]]
    visited_indicators: Set[str]
    infrastructure_map: List[Dict[str, Any]]
    final_summary: str

# --- 3. DEFINE THE AGENTS AND NODES ---

def create_agent(llm: ChatVertexAI, tools: list, system_prompt: str):
    """Factory function to create a new agent executor."""
    functions = [format_tool_to_openai_function(t) for t in tools]
    llm_with_tools = llm.bind(functions=functions)
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        MessagesPlaceholder(variable_name="messages"),
        MessagesPlaceholder(variable_name="agent_scratchpad"),
    ])
    agent_runnable = (
        {
            "messages": lambda x: x["messages"],
            "agent_scratchpad": lambda x: format_to_tool_messages(x["intermediate_steps"]),
        }
        | prompt
        | llm_with_tools
        | ToolsAgentOutputParser()
    )
    return AgentExecutor(agent=agent_runnable, tools=tools, handle_parsing_errors=True)

def exploration_node(state: GraphState, pivoting_agent: Runnable, harvester_chain: Runnable) -> GraphState:
    """Node that runs the PivotingAgent to explore new indicators."""
    if not state["indicators_to_visit"]:
        return state

    indicator_data = state["indicators_to_visit"].pop(0)
    indicator_value = indicator_data["value"]
    
    if indicator_value in state["visited_indicators"]:
        return state
    state["visited_indicators"].add(indicator_value)

    # 1. Pivot Agent runs to find related indicators and context
    prompt_text = f"Investigate the indicator: {indicator_value}. Use your tools to find all directly related IPs or domains. Also, perform a quick web search on the indicator itself to see if it's part of a known campaign."
    result = pivoting_agent.invoke({"messages": [HumanMessage(content=prompt_text)]})
    agent_output = result["output"]
    state["infrastructure_map"].append({"source": indicator_value, "result": agent_output})
    
    # 2. Harvester Chain extracts new indicators from the agent's text output
    harvester_prompt = f"You are a parser. Read the following text and extract all IP addresses and domains. Do not include the source indicator. Here is the text:\n\n{agent_output}"
    new_indicators = harvester_chain.invoke({"input": harvester_prompt})

    # 3. Add the harvested indicators back to the list to visit for the next loop
    for new_indicator in new_indicators.get("indicators", []):
        if new_indicator["value"] not in state["visited_indicators"]:
            st.write(f"🌱 Harvester found new indicator to visit: {new_indicator['value']}")
            state["indicators_to_visit"].append(new_indicator)

    state["current_depth"] += 1
    return state

def summarization_node(state: GraphState, correlator_agent: Runnable) -> GraphState:
    """Node that runs the CorrelatorAgent to generate the final report."""
    map_as_string = json.dumps(state["infrastructure_map"], indent=2)
    prompt_text = f"Analyze the following threat infrastructure map. Identify key hubs, summarize the campaign's likely purpose, and provide a comprehensive report in Markdown.\n\n{map_as_string}"
    result = correlator_agent.invoke({"messages": [HumanMessage(content=prompt_text)]})
    state["final_summary"] = result["output"]
    return state

def should_continue(state: GraphState) -> str:
    """Router that decides whether to continue exploring or end."""
    if state["current_depth"] >= state["max_depth"] or not state["indicators_to_visit"]:
        return "end"
    else:
        return "continue"

# --- Main Streamlit App ---
st.title("🕸️ Multi-Agent Threat Infrastructure Mapper")
st.markdown("Provide an initial file hash. Two AI agents—a Pivoter and a Correlator—will collaborate to map out the threat infrastructure using `langgraph`.")

# --- Secrets and Configuration Check ---
if not all([os.getenv("VIRUSTOTAL_API_KEY"), os.getenv("GCP_PROJECT_ID"), os.getenv("SERPAPI_API_KEY")]):
    st.error("FATAL ERROR: One or more required environment variables are missing (VIRUSTOTAL_API_KEY, GCP_PROJECT_ID, SERPAPI_API_KEY).")
else:
    # --- User Input Fields ---
    col1, col2 = st.columns(2)
    with col1:
        initial_hash = st.text_input("Initial File Hash:", value="ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa")
    with col2:
        max_depth = st.number_input("Max Exploration Depth:", min_value=1, max_value=6, value=6)

    if st.button("Begin Investigation", type="primary"):
        st.subheader("Mission Log")
        log_container = st.container()
        final_report_placeholder = st.empty()
        
        try:
            # --- Initialize Agents AND the Harvester Chain ---
            llm = ChatVertexAI(project=os.getenv("GCP_PROJECT_ID"), model_name="gemini-2.5-pro", temperature=0.0, convert_system_message_to_human=True)
            
            pivoting_tools = [get_contacted_domains, get_contacted_ips, get_ip_resolutions, web_search_for_threat]
            pivoting_agent = create_agent(llm, pivoting_tools, "You are a threat intelligence 'Pivoting Bot'. Your job is to take a single indicator and find all directly connected indicators and basic context. Return your findings as a block of text.")
            
            correlator_agent = create_agent(llm, [], "You are a senior threat analyst. You will be given a JSON map of infrastructure. Analyze the connections and write a summary report.")

            # Create the Harvester Chain with JSON output
            harvester_parser = JsonOutputParser(pydantic_object=False)
            harvester_prompt = ChatPromptTemplate.from_messages([
                SystemMessage(content="You are a parser. Your job is to extract IP addresses and domains from text. You must respond ONLY with a JSON object containing a single key 'indicators' which is a list of dictionaries. Each dictionary must have 'type' ('ip' or 'domain') and 'value' keys."),
                HumanMessage(content="{input}")
            ])
            harvester_chain = harvester_prompt | llm | harvester_parser

            # --- Define the Graph ---
            workflow = StateGraph(GraphState)
            workflow.add_node("explore", lambda s: exploration_node(s, pivoting_agent, harvester_chain))
            workflow.add_node("summarize", lambda s: summarization_node(s, correlator_agent))
            workflow.add_conditional_edges("explore", should_continue, {"continue": "explore", "end": "summarize"})
            workflow.add_edge("summarize", END)
            workflow.set_entry_point("explore")
            app = workflow.compile()
            
            # --- Set Initial State ---
            initial_state = {
                "initial_indicator": initial_hash,
                "max_depth": max_depth,
                "current_depth": 0,
                "indicators_to_visit": [{"type": "file", "value": initial_hash}],
                "visited_indicators": set(),
                "infrastructure_map": [],
                "final_summary": ""
            }
            
            # --- Stream the Graph Execution ---
            with st.spinner("Multi-agent investigation in progress..."):
                for chunk in app.stream(initial_state, {"recursion_limit": 15}):
                    node_name = list(chunk.keys())[0]
                    node_state = chunk[node_name]
                    
                    with log_container.container():
                        st.markdown(f'<div class="node-box"><div class="node-title">Executing Node: <strong>{node_name.upper()}</strong></div></div>', unsafe_allow_html=True)
                        if node_name == "explore":
                             st.write(f"**Depth:** {node_state['current_depth']} / {node_state['max_depth']}")
                             st.write(f"**Visiting:** `{list(node_state['visited_indicators'])[-1]}`")
                             st.write("**Pivoting Agent Findings:**")
                             st.text(node_state['infrastructure_map'][-1]['result'])
                        st.divider()

            # --- Display Final Report ---
            final_state = chunk[list(chunk.keys())[0]]
            with final_report_placeholder.container():
                st.subheader("Final Threat Intelligence Report")
                st.markdown(final_state.get("final_summary", "No summary was generated."))

        except Exception as e:
            st.error(f"An error occurred during the investigation: {e}")