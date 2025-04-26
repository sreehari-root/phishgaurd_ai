import streamlit as st
from src import core_analyzer
from src import utils
from src.core_analyzer import RISK_THRESHOLDS # Import thresholds for coloring
import json # To pretty print dicts/json
import pandas as pd # To display headers nicely
from datetime import datetime # For export filename timestamp

st.set_page_config(page_title="PhishGuard AI ++", layout="wide", initial_sidebar_state="collapsed")

# --- Session State Initialization ---
# Ensure keys exist before accessing them
default_session_state = {
    'history': [],
    'sender': "",
    'subject': "",
    'body': "",
    'raw_source': "",
    'latest_result': None # Store the latest analysis result
}
for key, default_value in default_session_state.items():
    if key not in st.session_state:
        st.session_state[key] = default_value

# --- Helper Function ---
def generate_export_text(result_data):
    """Generates a simple text summary for export."""
    if not result_data or result_data.get("error"):
        return "No valid analysis data to export."

    input_sum = result_data.get('input_summary', {})
    ts = input_sum.get('timestamp', 'N/A')
    score = result_data.get('risk_score', 'N/A')

    summary = f"PhishGuard AI Analysis Report\n"
    summary += f"=============================\n"
    summary += f"Timestamp: {ts}\n"
    summary += f"Input Mode: {input_sum.get('mode', 'N/A')}\n"
    summary += f"Risk Score: {score}/100\n\n"

    summary += f"AI Explanation:\n-----------------\n{result_data.get('alert_explanation', 'N/A')}\n\n"

    summary += f"Contributing Factors:\n---------------------\n"
    factors = result_data.get('contributing_factors', {})
    if factors:
        for key, value in factors.items():
            summary += f"- {key}: {value}\n"
    else:
        summary += "- None significant\n"

    summary += f"\n--- Details ---\n"
    summary += f"Analysis Duration: {result_data.get('analysis_duration_seconds'):.2f} seconds\n"

    if result_data.get("parsed_headers"):
        summary += f"\nParsed Headers:\n{json.dumps(result_data.get('parsed_headers', {}), indent=2)}\n"

    summary += f"\nAttachment Analysis:\n{json.dumps(result_data.get('attachment_analysis', {}), indent=2)}\n"
    summary += f"\nExtracted URLs:\n{json.dumps(result_data.get('extracted_urls', []), indent=2)}\n"
    summary += f"\nURL Blocklist Check: {'Yes' if result_data.get('is_url_blocklisted_display') else 'No'}\n"
    if result_data.get('blocklisted_url_found'):
        summary += f"Blocklisted URL Found: {result_data.get('blocklisted_url_found')}\n"

    summary += f"\nAI Text Analysis (JSON):\n{json.dumps(result_data.get('text_analysis', {}), indent=2)}\n"
    summary += f"\nAI URL Analysis Detail (JSON):\n{json.dumps(result_data.get('url_analysis_detail', {}), indent=2)}\n"

    return summary


# --- Main App UI ---
st.title("🎣 PhishGuard AI Sentinel ++")
st.caption("Enhanced AI analysis for phishing, social engineering, and suspicious indicators using Google Gemini.")

# --- Input Selection Tabs ---
input_tabs = ["Manual Input", "Paste Raw Email Source"]
analysis_mode_selected = st.radio("Select Input Mode:", input_tabs, horizontal=True, label_visibility="collapsed")

analysis_triggered = False
input_data = {}
# Clear other input mode state when switching tabs
if analysis_mode_selected == "Manual Input":
    st.session_state['raw_source'] = ""
else:
    st.session_state['sender'] = ""
    st.session_state['subject'] = ""
    st.session_state['body'] = ""

# --- Input Area based on selected tab ---
if analysis_mode_selected == "Manual Input":
    st.header("Analyze Manually Entered Content")
    # Load Sample Data Buttons
    st.markdown("Load Sample Data:")
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Subtle Phishing", key="b1", use_container_width=True):
            sample = utils.generate_sample_input("phishing_subtle")
            st.session_state['sender'] = sample["sender"]
            st.session_state['subject'] = sample["subject"]
            st.session_state['body'] = sample["body"]
    with col2:
        if st.button("Urgent Phishing", key="b2", use_container_width=True):
             sample = utils.generate_sample_input("phishing_urgent")
             st.session_state['sender'] = sample["sender"]
             st.session_state['subject'] = sample["subject"]
             st.session_state['body'] = sample["body"]
    with col3:
         if st.button("Benign Message", key="b3", use_container_width=True):
             sample = utils.generate_sample_input("benign")
             st.session_state['sender'] = sample["sender"]
             st.session_state['subject'] = sample["subject"]
             st.session_state['body'] = sample["body"]

    sender_input = st.text_input("Sender Email:", key='sender', placeholder="e.g., sender@example.com")
    subject_input = st.text_input("Subject:", key='subject', placeholder="e.g., Important Update")
    body_input = st.text_area("Email/Message Body:", height=200, key='body', placeholder="Paste the message content here...")

    if st.button("Analyze Manual Input", type="primary", key="analyze_manual", use_container_width=True):
        if not body_input:
            st.error("Please enter message body text to analyze.")
        else:
            input_data = {
                "sender": sender_input,
                "subject": subject_input,
                "body": body_input
            }
            analysis_triggered = True
            mode_selected = "manual"


elif analysis_mode_selected == "Paste Raw Email Source":
    st.header("Analyze Full Email Source (Headers + Body)")
    st.caption("Paste the complete raw source of the email (often found via 'Show Original' or 'View Source' in email clients). This enables header and attachment analysis.")
    raw_source_input = st.text_area("Paste Raw Email Source Here:", height=350, key='raw_source', placeholder="Paste the full source, starting with headers like 'Return-Path:' or 'Received:'...")

    if st.button("Analyze Raw Source", type="primary", key="analyze_raw", use_container_width=True):
        if not raw_source_input:
            st.error("Please paste the raw email source to analyze.")
        else:
            # Basic check if it looks like headers are included
            if not any(h in raw_source_input[:500] for h in ["Received:", "From:", "Subject:", "Date:", "Return-Path:"]):
                 st.warning("Input doesn't seem to start with typical email headers. Analysis might be less accurate.", icon="⚠️")
            input_data = {"raw_source": raw_source_input}
            analysis_triggered = True
            mode_selected = "raw_source"


# --- Analysis Execution and Results Display ---
st.divider()
st.header("Analysis Results")

analysis_in_progress = False # Flag to manage spinner state

if analysis_triggered:
    analysis_in_progress = True
    # Clear previous latest result before new analysis
    st.session_state['latest_result'] = None
    with st.spinner(f"Analyzing using {mode_selected} mode... Contacting AI..."):
        try:
            # Call the core analyzer with the selected mode
            results = core_analyzer.analyze(input_data, analysis_mode=mode_selected)
            st.session_state['latest_result'] = results # Store latest result

            # Add result to history if successful
            if not results.get("error"):
                st.session_state.history.insert(0, results) # Add to beginning
                if len(st.session_state.history) > 10: # Keep max history size
                    st.session_state.history.pop()

        except Exception as e:
            st.error(f"A critical error occurred during the analysis process: {e}")
            st.session_state['latest_result'] = {"error": f"Critical failure: {e}"} # Store error state
            import traceback
            st.error("Traceback:")
            st.code(traceback.format_exc()) # Show full traceback for debugging
        finally:
             analysis_in_progress = False # Ensure spinner stops

# --- Display Latest Analysis Result (if available) ---
latest_result_data = st.session_state['latest_result']

if latest_result_data:
    if latest_result_data.get("error"):
        st.error(f"Previous Analysis Error: {latest_result_data['error']}")
    else:
        score = latest_result_data.get("risk_score", 0)
        explanation = latest_result_data.get("alert_explanation", "No explanation available.")
        contributing_factors = latest_result_data.get("contributing_factors", {})
        text_analysis_details = latest_result_data.get("text_analysis", {})
        url_analysis_details = latest_result_data.get("url_analysis_detail", {}) # Note key change
        extracted_urls = latest_result_data.get("extracted_urls", [])
        attachment_analysis = latest_result_data.get("attachment_analysis", {})
        parsed_headers = latest_result_data.get("parsed_headers")
        duration = latest_result_data.get('analysis_duration_seconds')

        # Display Score and Explanation
        st.subheader(f"Overall Risk Score: {score}/100")
        if duration: st.caption(f"Analysis completed in {duration:.2f} seconds")

        # Color coding based on risk thresholds
        if score >= RISK_THRESHOLDS["HIGH"]:
            st.error(explanation, icon="🚨")
        elif score >= RISK_THRESHOLDS["MEDIUM"]:
            st.warning(explanation, icon="⚠️")
        elif score >= RISK_THRESHOLDS["LOW"]:
             st.info(explanation, icon="💡")
        else: # score < LOW threshold
            st.success(explanation, icon="✅")

        # Display Contributing Factors
        st.subheader("Key Factors Influencing Score:")
        if contributing_factors:
            factor_items = list(contributing_factors.items())
            num_cols = min(len(factor_items), 3) # Use up to 3 columns
            if num_cols > 0:
                 cols = st.columns(num_cols)
                 for i, (factor, value) in enumerate(factor_items):
                     with cols[i % num_cols]:
                          st.markdown(f"- **{factor}:** {value}")
        else:
            st.info("No specific high-risk factors identified contributing significantly to the score.")

        # Display Details in Expander
        with st.expander("Show Detailed Analysis Breakdown", expanded=False):
            if parsed_headers:
                 st.markdown("**Parsed Email Headers (Basic):**")
                 try:
                     # Filter out potentially very long Received headers for cleaner display
                     display_headers = {k: (v[:150] + '...' if isinstance(v, str) and len(v) > 150 else v)
                                        for k, v in parsed_headers.items() if v} # Also filter None values
                     # Convert to list of dicts for better st.dataframe handling
                     header_df_data = [{"Header": k, "Value": v} for k,v in display_headers.items()]
                     st.dataframe(header_df_data, use_container_width=True)
                 except Exception as e:
                      st.json(parsed_headers) # Fallback to JSON view
            elif latest_result_data.get('input_summary', {}).get('mode') == 'manual':
                 st.markdown("**Basic Checks (Manual Mode):**")
                 sender_checks = latest_result_data.get("sender_check_result_display", {})
                 st.write(f"- Sender SPF Check (Simulated): {sender_checks.get('spf', 'N/A')}")
                 st.write(f"- Sender DKIM Check (Simulated): {sender_checks.get('dkim', 'N/A')}")

            st.markdown("**URL Analysis:**")
            st.write(f"- URL found in Blocklist: {'Yes' if latest_result_data.get('is_url_blocklisted_display') else 'No'}")
            if latest_result_data.get("blocklisted_url_found"):
                st.write(f"  - Blocklisted URL: `{latest_result_data.get('blocklisted_url_found')}`")
            st.write(f"- Extracted URLs ({len(extracted_urls)}):")
            if extracted_urls:
                st.json(extracted_urls) # Show list of URLs

            if url_analysis_details:
                 st.markdown("**AI URL Analysis Detail (Simulated):**")
                 for url, analysis in url_analysis_details.items():
                     st.write(f"Analysis for URL: `{url}`")
                     if isinstance(analysis, dict) and analysis.get("error"):
                         st.error(f"URL Analysis Error: {analysis['error']}")
                     elif isinstance(analysis, dict):
                         st.json(analysis) # Display raw JSON from Gemini
                     else:
                         st.write("URL analysis data in unexpected format.")

            st.markdown("**Attachment Analysis:**")
            st.write(f"- Attachments Found: {len(attachment_analysis.get('names', []))}")
            if attachment_analysis.get('names'):
                 st.write(f"  - Names: `{', '.join(attachment_analysis.get('names'))}`")
            st.write(f"- Suspicious Attachments Found: {'Yes' if attachment_analysis.get('found_suspicious') else 'No'}")
            if attachment_analysis.get('suspicious_files'):
                st.warning(f"  - Suspicious Names Flagged: `{', '.join(attachment_analysis.get('suspicious_files'))}`")

            st.markdown("**AI Text Content Analysis Details:**")
            if isinstance(text_analysis_details, dict) and text_analysis_details.get("error"):
                st.error(f"Text Analysis Error: {text_analysis_details['error']}")
                if text_analysis_details.get("raw_response"):
                     st.caption("Raw AI Response (Error Case):")
                     st.code(text_analysis_details.get("raw_response"), language="text")
            elif isinstance(text_analysis_details, dict):
                st.json(text_analysis_details) # Display the raw JSON from Gemini
            else:
                 st.write("Text analysis details unavailable or in unexpected format.")

    # --- Export Button ---
    if latest_result_data and not latest_result_data.get("error"):
         export_text = generate_export_text(latest_result_data)
         ts_str = latest_result_data.get('input_summary', {}).get('timestamp', '').replace(' ','_').replace(':','')
         st.download_button(
             label="📋 Export Last Analysis Summary",
             data=export_text,
             file_name=f"PhishGuard_Analysis_{ts_str}.txt",
             mime="text/plain",
             use_container_width=True
         )

elif not analysis_in_progress: # Only show if not loading and no results yet
     st.info("Enter message details above or paste raw source and click Analyze.")


# --- Analysis History Display ---
st.divider()
st.header("Recent Analysis History (Last 10)")
if not st.session_state.history:
    st.info("No analyses performed yet in this session.")
else:
    # Allow clearing history
    if st.button("Clear History", key="clear_hist"):
        st.session_state.history = []
        st.rerun() # Rerun to reflect cleared history immediately

    for i, entry in enumerate(st.session_state.history):
        input_sum = entry.get("input_summary", {})
        score = entry.get("risk_score", "N/A")
        ts = input_sum.get("timestamp", "N/A")
        subj = input_sum.get("subject_input", "[No Subject]")
        mode = input_sum.get("mode", "N/A")
        exp_key = f"hist_exp_{i}"

        # Determine color based on score for the expander label
        color = "grey"
        if isinstance(score, int):
            if score >= RISK_THRESHOLDS["HIGH"]: color = "red"
            elif score >= RISK_THRESHOLDS["MEDIUM"]: color = "orange"
            elif score >= RISK_THRESHOLDS["LOW"]: color = "blue"
            else: color = "green"

        label = f":{color}[{ts} | Score: {score} | Mode: {mode.capitalize()} | Subject: {subj[:50]}{'...' if len(subj)>50 else ''}]"

        with st.expander(label, expanded=(i==0)): # Expand latest by default
            st.markdown(f"**Explanation:** {entry.get('alert_explanation', 'N/A')}")
            st.markdown("**Factors:**")
            factors = entry.get('contributing_factors', {})
            if factors:
                 st.json(factors)
            else:
                 st.write("None significant.")
            # Optional: Button to view full details? Could get complex.


# --- Footer or Info Section ---
st.divider()
st.caption("PhishGuard AI Sentinel ++ | CloudSEK AI in Cybersecurity Hackathon Prototype")