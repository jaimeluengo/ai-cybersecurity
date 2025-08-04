import streamlit as st
import os
import json
import requests
import re
from typing import List, Set, Dict, Any, TypedDict

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
st.set_page_config(page_title="Multi-Agent Threat Mapper", page_icon="🕸️", layout="wide")
st.markdown("""
<style>
    .reportview-container { background: #f0f2f6; }
    h1 { color: #8A2BE2; }
    .node-box { border: 2px solid #ddd; border-radius: 10px; padding: 1rem; margin-bottom: 1rem; }
    .node-title { font-weight: bold; color: #4A5568; margin-bottom: 0.5rem; }
</style>
""", unsafe_allow_html=True)


# --- Tools ---
def _vt_request(endpoint: str, api_key: str):
    if not api_key: return {"error": "VirusTotal API key not set."}
    url = f"https://www.virustotal.com/api/v3/{endpoint}"; headers = {"x-apikey": api_key, "Accept": "application/json"}
    try: response = requests.get(url, headers=headers); response.raise_for_status(); return response.json()
    except requests.exceptions.HTTPError as e: return {"error": f"HTTP Error: {e.response.status_code}", "details": e.response.text}
@tool
def get_contacted_domains(file_hash: str) -> dict:
    """Finds domains contacted by a specific file (malware)."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY"); return _vt_request(f"files/{file_hash}/contacted_domains", api_key)
@tool
def get_contacted_ips(file_hash: str) -> dict:
    """Finds IP addresses contacted by a specific file (malware)."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY"); return _vt_request(f"files/{file_hash}/contacted_ips", api_key)
@tool
def get_ip_resolutions(domain: str) -> dict:
    """Finds IP addresses that a domain has resolved to."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY"); return _vt_request(f"domains/{domain}/resolutions", api_key)
@tool
def web_search_for_threat(query: str) -> str:
    """Performs a web search to find context on threats, domains, IPs, or hashes."""
    if not os.getenv("SERPAPI_API_KEY"): return "Error: SERPAPI_API_KEY environment variable is not set."
    search = SerpAPIWrapper(); return search.run(query)

def harvest_indicators_from_text(text: str) -> List[Dict[str, str]]:
    """Uses regular expressions to reliably extract IPs and domains from text."""
    # Regex for IPv4 addresses
    ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
    
    found_ips = re.findall(ip_pattern, text)
    found_domains = re.findall(domain_pattern, text)
    
    # Filter out common false positives from domains
    common_false_positives = ['microsoft.com', 'akamai.net', 'sectigo.com']
    filtered_domains = [d for d in found_domains if d.lower() not in common_false_positives and not d.endswith('.arpa')]

    indicators = []
    # Use a set to store found values to avoid duplicates
    seen = set()

    for ip in found_ips:
        if ip not in seen:
            indicators.append({"type": "ip", "value": ip})
            seen.add(ip)
    
    for domain in filtered_domains:
        if domain not in seen:
            indicators.append({"type": "domain", "value": domain})
            seen.add(domain)
            
    return indicators

class GraphState(TypedDict):
    initial_indicator: str
    max_depth: int
    current_depth: int
    indicators_to_visit: List[Dict[str, str]]
    visited_indicators: Set[str]
    infrastructure_map: List[Dict[str, Any]]
    final_summary: str
    harvester_log: List[str]


def create_agent(llm: ChatVertexAI, tools: list, system_prompt: str):
    functions = [format_tool_to_openai_function(t) for t in tools]
    llm_with_tools = llm.bind(functions=functions)
    prompt = ChatPromptTemplate.from_messages([("system", system_prompt), MessagesPlaceholder(variable_name="messages"), MessagesPlaceholder(variable_name="agent_scratchpad"),])
    agent_runnable = ({"messages": lambda x: x["messages"], "agent_scratchpad": lambda x: format_to_tool_messages(x["intermediate_steps"]),} | prompt | llm_with_tools | ToolsAgentOutputParser())
    return AgentExecutor(agent=agent_runnable, tools=tools, handle_parsing_errors=True)

def exploration_node(state: GraphState, pivoting_agent: Runnable) -> GraphState:
    """Node that runs the PivotingAgent to explore new indicators."""
    state["harvester_log"] = []
    if not state["indicators_to_visit"]: return state

    indicator_data = state["indicators_to_visit"].pop(0)
    indicator_value = indicator_data["value"]
    
    if indicator_value in state["visited_indicators"]: return state
    state["visited_indicators"].add(indicator_value)

    prompt_text = f"Investigate the indicator: {indicator_value}. Use your tools to find all directly related IPs or domains. Also, perform a quick web search on the indicator itself to see if it's part of a known campaign."
    result = pivoting_agent.invoke({"messages": [HumanMessage(content=prompt_text)]})
    agent_output = result["output"]
    state["infrastructure_map"].append({"source": indicator_value, "result": agent_output})
    
    new_indicators = harvest_indicators_from_text(agent_output)

    for new_indicator in new_indicators:
        if new_indicator["value"] not in state["visited_indicators"]:
            state["harvester_log"].append(f"🌱 Regex Harvester extracted new indicator to visit: {new_indicator['value']}")
            state["indicators_to_visit"].append(new_indicator)

    state["current_depth"] += 1; return state

def summarization_node(state: GraphState, correlator_agent: Runnable) -> GraphState:
    map_as_string = json.dumps(state["infrastructure_map"], indent=2); prompt_text = f"Analyze the following threat infrastructure map. Identify key hubs, summarize the campaign's likely purpose, and provide a comprehensive report in Markdown.\n\n{map_as_string}";
    result = correlator_agent.invoke({"messages": [HumanMessage(content=prompt_text)]}); state["final_summary"] = result["output"]; return state
def should_continue(state: GraphState) -> str:
    if state["current_depth"] >= state["max_depth"] or not state["indicators_to_visit"]: return "end"
    else: return "continue"

st.title("🕸️ Multi-Agent Threat Infrastructure Mapper")
st.markdown("Provide an initial file hash. AI agents will collaborate to map out the threat infrastructure, showing their work in real time.")

if not all([os.getenv("VIRUSTOTAL_API_KEY"), os.getenv("GCP_PROJECT_ID"), os.getenv("SERPAPI_API_KEY")]):
    st.error("FATAL ERROR: One or more required environment variables are missing.")
else:
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
            # --- Initialize Agents & Chains ---
            llm = ChatVertexAI(project=os.getenv("GCP_PROJECT_ID"), model_name="gemini-2.5-pro", temperature=0.0, convert_system_message_to_human=True)
            pivoting_tools = [get_contacted_domains, get_contacted_ips, get_ip_resolutions, web_search_for_threat]
            pivoting_agent = create_agent(llm, pivoting_tools, "You are a threat intelligence 'Pivoting Bot'. Your job is to take a single indicator and find all directly connected indicators and basic context. Return your findings as a block of text.")
            correlator_agent = create_agent(llm, [], "You are a senior threat analyst. You will be given a JSON map of infrastructure. Analyze the connections and write a summary report.")

            # --- Define the Graph ---
            workflow = StateGraph(GraphState)
            workflow.add_node("explore", lambda s: exploration_node(s, pivoting_agent))
            workflow.add_node("summarize", lambda s: summarization_node(s, correlator_agent))
            workflow.add_conditional_edges("explore", should_continue, {"continue": "explore", "end": "summarize"})
            workflow.add_edge("summarize", END)
            workflow.set_entry_point("explore")
            app = workflow.compile()
            
            # --- Set Initial State ---
            initial_state = { "initial_indicator": initial_hash, "max_depth": max_depth, "current_depth": 0, "indicators_to_visit": [{"type": "file", "value": initial_hash}], "visited_indicators": set(), "infrastructure_map": [], "final_summary": "", "harvester_log": [] }
            
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
                             if node_state.get("harvester_log"):
                                 for msg in node_state["harvester_log"]:
                                     st.info(msg) # Using st.info for better visibility
                        st.divider()

            final_state = chunk[list(chunk.keys())[0]]
            with final_report_placeholder.container():
                st.subheader("Final Threat Intelligence Report")
                st.markdown(final_state.get("final_summary", "No summary was generated."))

        except Exception as e:
            st.error(f"An error occurred during the investigation: {e}")
            st.exception(e)