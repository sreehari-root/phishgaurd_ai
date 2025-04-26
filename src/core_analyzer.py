# src/core_analyzer.py (Tuned Version)

from . import gemini_handler
from . import basic_checks
from . import utils
import json # For potential header display
from datetime import datetime # For timestamping results
import re # For checking domain in scoring
import urllib.parse # For domain checking function

# Define risk score thresholds
RISK_THRESHOLDS = {
    "VERY_LOW": 20,
    "LOW": 40, # Start generating explanation from here
    "MEDIUM": 70,
    "HIGH": 90,
    "VERY_HIGH": 100
}

# Define weights - TUNED to reduce false positives
RISK_WEIGHTS = {
    # Basic Checks
    "URL_BLOCKLISTED": 50, # Still high impact
    "SENDER_SPF_FAIL_SIM": 3, # Very low weight for simulated checks
    "SENDER_DKIM_FAIL_SIM": 3,

    # Header Analysis (from AI) - Based on reliable signals if present
    "HEADER_AUTH_FAIL": 30, # SPF/DKIM/DMARC fail is a strong signal
    "HEADER_FROM_MISMATCH": 15, # Still relevant
    "HEADER_SUSPICIOUS_ORIGIN": 10, # Context dependent

    # Attachment Checks
    "ATTACHMENT_SUSPICIOUS_NAME": 50, # Still very high impact

    # Gemini Text Analysis Indicators - Reduced weights for potentially ambiguous ones
    "INTENT_CREDENTIALS": 20,
    "INTENT_PAYMENT": 25,
    "INTENT_MALWARE": 35,
    "INTENT_URGENCY_HIGH": 10, # Only apply if AI explicitly flags high urgency/threat
    "IMPERSONATION_CONF_HIGH": 15, # Reduced significantly
    "IMPERSONATION_CONF_MEDIUM": 5, # Reduced significantly
    "TACTIC_PRESENT": 3, # Very low base score for just mentioning a tactic
    "TACTIC_INTIMIDATION": 15, # Keep higher weight for clear manipulation
    "LINGUISTIC_ANOMALIES_HIGH": 5, # Low impact unless severe
    "LINGUISTIC_ANOMALIES_MEDIUM": 2,

    # Gemini URL Analysis (Simulated)
    "URL_CONTENT_CREDENTIAL_HARVESTING": 30,
    "URL_CONTENT_MALWARE": 35,
    "URL_BRAND_IMPERSONATION_HIGH": 25, # Weight applied if AI *specifically* flags high risk impersonation despite domain checks
    "URL_SUSPICIOUS_PATTERN": 10, # Applied conditionally below
    "URL_RISK_HIGH": 15, # AI's overall assessment of the URL structure
}

# List of known good domains for scoring adjustment
KNOWN_GOOD_DOMAINS_FOR_SCORING = [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com',
    'linkedin.com', 'facebook.com', 'twitter.com', 'youtube.com',
    'docs.google.com', 'drive.google.com', 'onedrive.live.com', 'dropbox.com',
    'outlook.com', 'office.com', 'live.com', 'gmail.com', 'projecthub.app' # Added projecthub.app
    # Add more well-known, trusted domains as needed
]

def is_domain_known_good(url_string):
    """Checks if the domain of a URL is in the known good list."""
    if not url_string: return False
    try:
        # Use urllib.parse which should be imported
        domain = urllib.parse.urlparse(url_string).netloc.lower()
        # Handle cases like "www.google.com" -> "google.com"
        if domain.startswith('www.'):
             domain = domain[4:]

        for good_domain in KNOWN_GOOD_DOMAINS_FOR_SCORING:
            # Check exact match or subdomain of known good
            if domain == good_domain or domain.endswith('.' + good_domain):
                return True
    except Exception as e:
        print(f"Error parsing URL for domain check: {url_string} - {e}")
        return False # Error parsing URL
    return False


def calculate_risk_score(factors):
    """Calculates a risk score based on weighted factors. (Tuned Logic)"""
    score = 0
    active_factors = {} # Stores human-readable factors contributing to the score

    # --- Basic & Header Checks ---
    blocklisted_url = factors.get('blocklisted_url')
    if blocklisted_url:
        score += RISK_WEIGHTS["URL_BLOCKLISTED"]
        # Ensure the factor key is unique and informative
        active_factors["URL Blocklist Hit"] = f"URL found in blocklist ({blocklisted_url})"

    # Only use simulated checks if headers failed parsing or weren't available
    if not factors.get("headers_parsed"):
        sender_check = factors.get("sender_check_result", {})
        sim_reasons = []
        if sender_check.get("spf") == "fail": score += RISK_WEIGHTS["SENDER_SPF_FAIL_SIM"]; sim_reasons.append("SPF Fail")
        if sender_check.get("dkim") == "fail": score += RISK_WEIGHTS["SENDER_DKIM_FAIL_SIM"]; sim_reasons.append("DKIM Fail")
        if sim_reasons: active_factors["Sender Check (Simulated)"] = ", ".join(sim_reasons)

    # Use AI Header Analysis if available
    header_analysis = factors.get("header_analysis_notes", "").lower()
    if factors.get("headers_parsed"):
        ai_header_notes = []
        # Check specific keywords indicating failure from AI analysis
        if "fail" in header_analysis and ("spf" in header_analysis or "dkim" in header_analysis or "dmarc" in header_analysis):
            score += RISK_WEIGHTS["HEADER_AUTH_FAIL"]
            ai_header_notes.append("Authentication Failed (SPF/DKIM/DMARC)")
        if "mismatch" in header_analysis and "from" in header_analysis:
            score += RISK_WEIGHTS["HEADER_FROM_MISMATCH"]
            ai_header_notes.append("From/Sender Mismatch")
        if "suspicious origin" in header_analysis or "unusual origin" in header_analysis:
            score += RISK_WEIGHTS["HEADER_SUSPICIOUS_ORIGIN"]
            ai_header_notes.append("Suspicious Origin Hint")
        if ai_header_notes:
            active_factors["AI Header Analysis"] = ". ".join(ai_header_notes)

    # --- Attachment Checks ---
    attachment_check = factors.get("attachment_check", {})
    if attachment_check.get("found_suspicious"):
        score += RISK_WEIGHTS["ATTACHMENT_SUSPICIOUS_NAME"]
        susp_files = ", ".join(attachment_check.get("suspicious_files",[]))
        active_factors["Attachment Analysis"] = f"Suspicious Names Found ({susp_files})"

    # --- Gemini Text Analysis (Tuned Scoring) ---
    text_analysis = factors.get("text_analysis", {})
    if isinstance(text_analysis, dict) and not text_analysis.get("error"): # Check it's a dict and no error
        intent = text_analysis.get("intent_urgency", "").lower()
        impersonation = text_analysis.get("impersonation_signals", "").lower()
        tactics = text_analysis.get("psychological_tactics", []) # Keep original case if list
        linguistic = text_analysis.get("linguistic_anomalies", "").lower()
        confidence = text_analysis.get("confidence_score", 0) # Get confidence score if available

        # Score Intents
        if "credential" in intent: score += RISK_WEIGHTS["INTENT_CREDENTIALS"]; active_factors["AI Text Intent"] = "Credential Harvesting Suspected"
        elif "payment" in intent or "invoice" in intent or "gift card" in intent: score += RISK_WEIGHTS["INTENT_PAYMENT"]; active_factors["AI Text Intent"] = "Payment Fraud Suspected"
        elif "malware" in intent or ("download" in intent and ("suspicious" in intent or "payload" in intent)): score += RISK_WEIGHTS["INTENT_MALWARE"]; active_factors["AI Text Intent"] = "Malware Delivery Suspected"

        # Score Urgency only if HIGH urgency mentioned by AI
        if "high" in intent or "immediate" in intent:
            score += RISK_WEIGHTS["INTENT_URGENCY_HIGH"]; active_factors["AI Text Urgency"] = "High"

        # Score Impersonation (Reduced weights) - Use confidence level
        if "high confidence" in impersonation: score += RISK_WEIGHTS["IMPERSONATION_CONF_HIGH"]; active_factors["AI Text Impersonation"] = "High Confidence"
        elif "medium confidence" in impersonation or "likely" in impersonation: score += RISK_WEIGHTS["IMPERSONATION_CONF_MEDIUM"]; active_factors["AI Text Impersonation"] = "Medium Confidence"

        # Score Tactics (Reduced base weight, focus on specific bad ones)
        if tactics:
             score += RISK_WEIGHTS["TACTIC_PRESENT"] # Low base score just for presence
             # Add extra only for clear manipulation tactics if score isn't already very high
             tactic_descriptions = []
             if any('intimidation' in str(t).lower() or 'threatening' in str(t).lower() for t in tactics):
                 if score < RISK_THRESHOLDS["HIGH"]: score += RISK_WEIGHTS["TACTIC_INTIMIDATION"]
                 tactic_descriptions.append("Intimidation/Threats")
             # Check for other significant tactics, but avoid over-penalizing combinations if score is low
             elif any('authority' in str(t).lower() or 'scarcity' in str(t).lower() or 'urgency' in str(t).lower() for t in tactics):
                  if score < RISK_THRESHOLDS["MEDIUM"]: score += 5 # Smaller boost for other common tactics
                  tactic_descriptions.append("Other Manipulative Tactics")

             if tactic_descriptions:
                  active_factors["AI Psycho. Tactics"] = ", ".join(list(set(tactic_descriptions))) # Show unique descriptions


        # Score Linguistic Anomalies (Reduced weights)
        if "high" in linguistic or "major" in linguistic: score += RISK_WEIGHTS["LINGUISTIC_ANOMALIES_HIGH"]; active_factors["AI Linguistic Anomalies"] = "High Severity"
        elif "medium" in linguistic: score += RISK_WEIGHTS["LINGUISTIC_ANOMALIES_MEDIUM"]; active_factors["AI Linguistic Anomalies"] = "Medium Severity"

    # --- Gemini URL Analysis (Simulated - Tuned Scoring) ---
    url_analysis = factors.get("url_analysis", {}) # Analysis dict for the first URL analyzed
    analyzed_url_str = factors.get("analyzed_url_str", "") # The actual URL string analyzed

    if isinstance(url_analysis, dict) and not url_analysis.get("error"): # Check it's a dict and no error
         content = url_analysis.get("likely_content_type", "").lower()
         brand_risk = url_analysis.get("brand_impersonation_risk", "").lower()
         patterns = url_analysis.get("suspicious_url_patterns", [])
         url_risk = url_analysis.get("overall_url_risk_assessment", "").lower()

         # Check if the domain is known good before applying penalties
         is_good_domain = is_domain_known_good(analyzed_url_str)

         # Score based on likely content
         if "credential harvesting" in content: score += RISK_WEIGHTS["URL_CONTENT_CREDENTIAL_HARVESTING"]; active_factors["Sim. URL Content"] = "Credential Harvesting Likely"
         if "malware" in content: score += RISK_WEIGHTS["URL_CONTENT_MALWARE"]; active_factors["Sim. URL Content"] = "Malware Delivery Likely"

         # Only add brand impersonation score if domain isn't known good AND AI flags high risk
         if brand_risk == "high" and not is_good_domain:
              score += RISK_WEIGHTS["URL_BRAND_IMPERSONATION_HIGH"]; active_factors["Sim. URL Brand Risk"] = "High (Non-Trusted Domain)"

         # Only add pattern score if domain isn't known good OR patterns are severe (like HTTP)
         if patterns:
              pattern_score_to_add = 0
              # Always penalize HTTP for sensitive content types
              if "http protocol" in str(patterns).lower() and ("credential" in content or "malware" in content):
                    pattern_score_to_add = RISK_WEIGHTS["URL_SUSPICIOUS_PATTERN"]
              # Penalize other patterns only if not a known good domain
              elif not is_good_domain:
                   pattern_score_to_add = RISK_WEIGHTS["URL_SUSPICIOUS_PATTERN"]

              if pattern_score_to_add > 0:
                   score += pattern_score_to_add
                   active_factors["Sim. URL Patterns"] = ", ".join(patterns)

         # Add score based on AI's overall URL risk assessment, less if good domain
         if url_risk == "high":
             score += RISK_WEIGHTS["URL_RISK_HIGH"] if not is_good_domain else 5 # Less penalty if known good domain
             active_factors["Sim. URL Risk Assess."] = "High"
         elif url_risk == "medium" and not is_good_domain:
             score += RISK_WEIGHTS["URL_RISK_HIGH"] / 2 # Half points if medium risk on non-trusted domain
             active_factors["Sim. URL Risk Assess."] = "Medium"


    # Clamp score between 0 and 100
    final_score = max(0, min(int(score), 100)) # Ensure integer score
    return final_score, active_factors


def analyze(input_data, analysis_mode="manual"):
    """
    Main analysis function. Handles different input modes. (Tuned Version)
    """
    start_time = datetime.now()
    sender, subject, body, raw_source = "", "", "", ""
    headers = None
    attachment_names = []
    results = {"analysis_start_time": start_time.isoformat()} # Store start time
    analysis_factors = {} # Re-initialize for each run

    # --- Input Processing ---
    if analysis_mode == "manual":
        sender = input_data.get("sender", "")
        subject = input_data.get("subject", "")
        body = input_data.get("body", "")
        if not body and not subject: return {"error": "No message body or subject provided for manual analysis."}
        # Simulate basic sender checks ONLY if headers aren't available
        analysis_factors["sender_check_result"] = basic_checks.simulate_sender_checks(sender)
        analysis_factors["headers_parsed"] = False

    elif analysis_mode == "raw_source":
        raw_source = input_data.get("raw_source", "")
        if not raw_source: return {"error": "No raw email source provided."}
        # Parse headers and body from raw source
        headers, body = utils.extract_basic_headers(raw_source)
        results["parsed_headers"] = headers # Store parsed headers
        if isinstance(headers, dict) and "Error" not in headers:
            subject = headers.get("Subject", "[No Subject Found]")
            from_header = headers.get("From", "")
            # Try to extract just the email address from the From header
            if '<' in from_header and '>' in from_header:
                 match = re.search(r'<([^>]+)>', from_header)
                 sender = match.group(1).strip() if match else from_header.strip() # Extract address within <>
            else:
                 sender = from_header.strip() if from_header else "[No Sender Found]"
            analysis_factors["headers_parsed"] = True
            # Indicate header analysis will be used instead of simulation
            analysis_factors["sender_check_result"] = {"spf": "N/A", "dkim": "N/A", "reason":"Using Header Analysis"}
        else: # Header parsing failed
            # Store the error note for potential scoring/display
            analysis_factors["header_analysis_notes"] = f"Header Parsing Failed: {headers.get('Error', 'Unknown Error')}"
            subject = "[Subject Unavailable]"
            sender = "[Sender Unavailable]"
            analysis_factors["headers_parsed"] = False
            analysis_factors["sender_check_result"] = {"spf": "N/A", "dkim": "N/A", "reason":"Header Parse Failed"}

        # Extract attachments from raw source regardless of header parse success
        attachment_names = utils.extract_attachment_names(raw_source)

    else: # Should not happen with radio buttons
        return {"error": "Invalid analysis mode specified."}


    # --- Store Input Summary ---
    # Use the sender/subject determined above
    results["input_summary"] = {
             "mode": analysis_mode, "sender_input": sender, "subject_input": subject,
             "timestamp": start_time.strftime("%Y-%m-%d %H:%M:%S")
    }

    # --- Common Analysis Steps ---
    # 1. Attachment Checks
    suspicious_files, found_suspicious = utils.check_suspicious_attachment_names(attachment_names)
    analysis_factors["attachment_check"] = {
        "names": attachment_names, "suspicious_files": suspicious_files, "found_suspicious": found_suspicious
    }
    results["attachment_analysis"] = analysis_factors["attachment_check"]

    # 2. Extract URLs from body
    urls = utils.extract_urls(body)
    results["extracted_urls"] = urls
    analysis_factors["contains_urls"] = bool(urls)

    # 3. Check URLs against Blocklist
    analysis_factors["is_url_blocklisted"] = False
    blocklisted_url_found = None
    if urls:
        for url in urls:
            if basic_checks.check_url_blocklist(url):
                analysis_factors["is_url_blocklisted"] = True
                results["blocklisted_url_found"] = url
                analysis_factors["blocklisted_url"] = url # Pass specific URL for scoring context
                blocklisted_url_found = url
                break # Stop after finding one
    # For display in app.py
    results["is_url_blocklisted_display"] = analysis_factors["is_url_blocklisted"]

    # 4. Gemini Text Analysis
    text_analysis_result = gemini_handler.analyze_text_content(subject, body, sender, headers=headers)
    results["text_analysis"] = text_analysis_result
    analysis_factors["text_analysis"] = text_analysis_result # Add raw analysis for scoring
    # Store AI's header notes separately if parsed ok and no error in AI response
    if analysis_factors["headers_parsed"] and isinstance(text_analysis_result, dict) and not text_analysis_result.get("error"):
        analysis_factors["header_analysis_notes"] = text_analysis_result.get("header_analysis_notes","")
    elif not analysis_factors["headers_parsed"]: # If headers weren't parsed, ensure note reflects that
         analysis_factors["header_analysis_notes"] = headers.get('Error', 'Headers Not Provided/Parsed') if isinstance(headers, dict) else 'Headers Not Provided/Parsed'


    # 5. Gemini URL Analysis (Simulated - Analyze first URL found for demo)
    analysis_factors["url_analysis"] = {} # Initialize for scoring
    results["url_analysis_detail"] = {} # Store detailed results per URL
    first_analyzed_url = None
    if urls:
         # Prioritize analyzing blocklisted URL if found, otherwise first URL
         url_to_analyze = blocklisted_url_found if blocklisted_url_found else urls[0]
         first_analyzed_url = url_to_analyze # Store which URL was analyzed
         analysis_factors["analyzed_url_str"] = first_analyzed_url # Pass to scoring function
         url_analysis_result = gemini_handler.analyze_url_simulated(url_to_analyze)
         results["url_analysis_detail"][url_to_analyze] = url_analysis_result
         # Use only the first URL's result for the main scoring factor (simplification)
         if isinstance(url_analysis_result, dict):
              analysis_factors["url_analysis"] = url_analysis_result # Add raw analysis for scoring


    # 6. Calculate Risk Score using TUNED logic
    score, contributing_factors = calculate_risk_score(analysis_factors)
    results["risk_score"] = score
    results["contributing_factors"] = contributing_factors

    # 7. Generate Alert Explanation (pass attachment info) using TUNED prompt
    results["alert_explanation"] = "Analysis complete." # Default message
    # Generate explanation based on RISK_THRESHOLDS['LOW']
    if score >= RISK_THRESHOLDS["LOW"]:
         results["alert_explanation"] = gemini_handler.generate_alert_explanation(
             score, contributing_factors, attachment_info=analysis_factors["attachment_check"]
         )
    elif score < RISK_THRESHOLDS["VERY_LOW"]: # Add explicit low risk message if needed
         results["alert_explanation"] = "**Very Low Risk:** Analysis indicates message is likely safe."


    # Add back sender check display info used by app.py (needed even if not used in scoring when headers are present)
    results["sender_check_result_display"] = analysis_factors.get("sender_check_result", {"spf": "N/A", "dkim": "N/A"})

    end_time = datetime.now()
    results["analysis_duration_seconds"] = (end_time - start_time).total_seconds()

    return results
