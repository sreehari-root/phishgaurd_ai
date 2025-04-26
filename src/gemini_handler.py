import os
import google.generativeai as genai
from dotenv import load_dotenv
import json
import time # For potential retries
import urllib.parse # Added for URL parsing in analyze_url_simulated

# Load API Key from .env file
load_dotenv()
API_KEY = os.getenv("GOOGLE_API_KEY")

# Global variable for model initialization status
gemini_model_initialized = False
model = None

if not API_KEY:
    print("Error: GOOGLE_API_KEY not found in .env file. AI features disabled.")
else:
    try:
        genai.configure(api_key=API_KEY)
        # Configure generative model options (adjust as needed)
        generation_config = {
          "temperature": 0.4, # Even lower temperature for more consistent analysis
          "top_p": 0.95,
          "top_k": 40,
          "max_output_tokens": 2048,
        }

        safety_settings = [
            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_ONLY_HIGH"},
            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_ONLY_HIGH"},
            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_ONLY_HIGH"},
            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_MEDIUM_AND_ABOVE"},
        ]

        # Initialize the model
        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            generation_config=generation_config,
            safety_settings=safety_settings
        )
        gemini_model_initialized = True
        print("Gemini model initialized successfully.")
    except Exception as e:
        print(f"Error initializing Google AI SDK or Gemini model: {e}. AI features disabled.")
        API_KEY = None


def _call_gemini_with_retry(prompt, expect_json=True, max_retries=2, delay=5):
    """Internal function to call Gemini API with basic retry logic."""
    if not gemini_model_initialized or not model:
        return {"error": "Gemini model not initialized."} if expect_json else "Error: Gemini model not initialized."

    attempts = 0
    while attempts <= max_retries:
        try:
            response = model.generate_content(prompt)
            if not response.parts:
                 feedback_reason = "Unknown"
                 if response.prompt_feedback and response.prompt_feedback.block_reason:
                     feedback_reason = response.prompt_feedback.block_reason.name
                 raise ValueError(f"Gemini response blocked or empty. Reason: {feedback_reason}. Feedback: {response.prompt_feedback}")

            response_text = response.text.strip()

            if expect_json:
                if response_text.startswith("```json"): response_text = response_text[7:]
                if response_text.endswith("```"): response_text = response_text[:-3]
                response_text = response_text.strip()
                if not response_text.startswith('{') or not response_text.endswith('}'):
                     raise json.JSONDecodeError("Response does not look like JSON.", response_text, 0)
                analysis_result = json.loads(response_text)
                return analysis_result # Success (JSON)
            else:
                 return response_text # Success (Plain text)

        except json.JSONDecodeError as e:
            print(f"Attempt {attempts+1}: Error decoding Gemini JSON response: {e}\nRaw response: {response.text if 'response' in locals() else 'N/A'}")
            return {"error": f"Failed to parse AI analysis response (JSON decode). Raw: {response.text if 'response' in locals() else 'N/A'}", "raw_response": response.text if 'response' in locals() else None}
        except ValueError as ve:
             print(f"Attempt {attempts+1}: Gemini response blocked or invalid: {ve}")
             return {"error": f"Gemini response blocked or invalid: {ve}"} if expect_json else f"Error: Gemini response blocked or invalid: {ve}"
        except Exception as e:
            print(f"Attempt {attempts+1}: Error during Gemini API call: {e}")
            if attempts < max_retries:
                print(f"Retrying in {delay} seconds...")
                time.sleep(delay)
            else:
                error_details = f"Error: {e}"
                if 'response' in locals() and hasattr(response, 'prompt_feedback') and response.prompt_feedback:
                     error_details += f" | Prompt Feedback: {response.prompt_feedback}"
                err_msg = f"Gemini API call failed after {max_retries+1} attempts. Details: {error_details}"
                return {"error": err_msg} if expect_json else f"Error: {err_msg}"
        attempts += 1


def analyze_text_content(subject, body, sender, headers=None):
    """
    Analyzes email/message content using Gemini for phishing/social engineering indicators.
    (Tuned Prompt for reducing false positives on legitimate emails)
    """
    if not gemini_model_initialized: return {"error": "Gemini model not initialized."}
    if not body and not headers: return {"error": "No body text or headers provided for analysis."}

    # --- Header Formatting Logic (Same as before) ---
    header_info_prompt = "[No header information provided or headers failed parsing]"
    if headers and isinstance(headers, dict) and "Error" not in headers:
         key_headers = {
             'From': headers.get('From'), 'To': headers.get('To'), 'Subject': headers.get('Subject'),
             'Return-Path': headers.get('Return-Path'), 'Reply-To': headers.get('Reply-To'),
             'Authentication-Results': headers.get('Authentication-Results'), 'Received_First': headers.get('Received_First'),
         }
         filtered_headers = {k: v for k, v in key_headers.items() if v}
         header_info_prompt = f"""
         Consider the following header information for additional context:
         ```json
         {json.dumps(filtered_headers, indent=2)}
         ```
         Specifically check:
         - Consistency between the claimed 'Sender' ('{sender}') and the 'From'/'Return-Path'/'Reply-To' headers.
         - Results of SPF, DKIM, DMARC in 'Authentication-Results' if present (e.g., 'dkim=pass', 'spf=fail').
         - Origin hints in the 'Received_First' header (is it plausible?).
         """
    elif headers and isinstance(headers, dict) and "Error" in headers:
         header_info_prompt = f"\nNote: There was an error parsing email headers: {headers['Error']}\n"
    # --- End Header Formatting ---

    # --- Tuned Main Prompt ---
    prompt = f"""
    You are a cybersecurity analyst AI. Analyze the following email content and context for phishing, social engineering, and malware indicators. Be cautious but **differentiate between normal business communication (like standard deadlines, professional signatures, legitimate links from known domains like google.com) and genuinely malicious tactics.** Provide your analysis ONLY as a JSON object with the specified keys.

    Input Data:
    Subject: "{subject}"
    Claimed Sender: "{sender}"
    {header_info_prompt}
    Body:
    ---
    {body if body else "[No body text provided or extracted]"}
    ---

    Required JSON Output Structure:
    {{
      "intent_urgency": "Categorize primary intent. Describe urgency level (e.g., High - Immediate Action Required/Threats, Medium - Standard Deadline/Request, Low - Informational). **Do not flag standard deadlines (like 'by Friday', 'EOD') as high urgency unless combined with explicit threats or extreme pressure.**",
      "sentiment_tone": "Describe overall tone (e.g., Professional, Urgent/Alarmist, Friendly/Deceptive, Threatening, Impersonal/Generic).",
      "impersonation_signals": "Identify impersonation attempts (Brand, Individual, Service). **Do not flag standard professional signatures (name, title, company) unless they clearly conflict with sender/context, seem fabricated, or request inappropriate actions.** Assess confidence (e.g., High, Medium, Low).",
      "psychological_tactics": ["List clearly identifiable malicious tactics (e.g., Authority [if unusual/coercive], Scarcity, Urgency [if extreme/threatening], Sympathy [if manipulative], Intimidation, Social Proof). **Avoid flagging normal requests, standard deadlines, or professional titles as malicious tactics unless context strongly suggests manipulation.** Empty list if none clear."],
      "linguistic_anomalies": "Note suspicious language (e.g., Major Grammar/Spelling Errors, Awkward Phrasing, Generic Language, Mismatched Formality). Rate severity (e.g., Low, Medium, High).",
      "header_analysis_notes": "Summarize key findings from headers (e.g., SPF/DKIM/DMARC Status from Auth-Results, From/Sender Mismatch, Suspicious Origin Hint from Received, Headers Seem Normal, Headers Not Provided/Parsed).",
      "url_analysis_required": true, # Boolean: Indicate if URLs requiring analysis were found in the body.
      "attachment_analysis_notes": "Comment briefly if attachments seem relevant to the threat based on context (e.g., 'Attachment mentioned - potential payload', 'No attachments relevant'). Actual attachment checks are separate.",
      "overall_assessment": "Provide a concise risk assessment based on *all* evidence. **Give weight to legitimacy signals like valid header authentication (if available) and links to known reputable domains (e.g., google.com, microsoft.com, etc.).** (e.g., Very High Risk - Likely Malicious Phishing, High Risk - Social Engineering Attempt, Medium Risk - Suspicious Indicators Warrant Caution, Low Risk - Likely Benign, Very Low Risk - Informational).",
      "confidence_score": "Estimate confidence in assessment (0-100)."
    }}

    Analyze carefully, considering context for legitimacy, differentiating business norms from threats, and respond ONLY with the JSON object.
    """
    # --- End Tuned Main Prompt ---

    return _call_gemini_with_retry(prompt, expect_json=True)


def analyze_url_simulated(url):
    """
    Simulates analyzing a URL's landing page content using Gemini based on URL patterns ONLY.
    (Tuned Prompt for reducing false positives on legitimate URLs)
    """
    if not gemini_model_initialized: return {"error": "Gemini model not initialized."}
    if not url: return {"error": "No URL provided for analysis."}

    # --- Simulation Logic (Same as before) ---
    simulated_content_description = f"The URL is: {url}."
    known_good_domains = ["google.com", "microsoft.com", "apple.com", "amazon.com", "github.com", "linkedin.com", "facebook.com", "twitter.com", "youtube.com", "docs.google.com", "drive.google.com", "onedrive.live.com", "dropbox.com"] # Add more if needed
    is_known_good = False
    try:
         parsed_uri = urllib.parse.urlparse(url)
         domain = parsed_uri.netloc.lower()
         path = parsed_uri.path.lower()
         # Check if domain or parent domain is known good
         for good_domain in known_good_domains:
              if domain == good_domain or domain.endswith('.' + good_domain):
                   is_known_good = True
                   simulated_content_description += f" Domain '{domain}' appears related to a known legitimate service ({good_domain})."
                   break # Stop checking once known good found

         if any(kw in domain or kw in path for kw in ["login", "verify", "signin", "recover", "account", "secure", "update", "webskr", "wp-admin", "admin"]):
             simulated_content_description += " URL path/domain suggests account actions or login page."
         if any(brand in domain for brand in ["paypa", "micros", "amazn", "googl", "appl", "bank", "office", "fedex", "dhl", "netflix", "wellsfargo", "chase"]) and not is_known_good:
             simulated_content_description += f" Domain '{domain}' might be attempting to impersonate a known brand."
         tld = domain.split('.')[-1]
         if tld in ['xyz', 'info', 'biz', 'top', 'live', 'icu', 'cyou', 'club', 'online', 'buzz', 'monster', 'pw', 'ga', 'ml', 'cf', 'gq']: # Added more free/abused TLDs
             simulated_content_description += f" It uses a TLD ('.{tld}') sometimes associated with phishing or spam."
         if domain.count('.') > 2 and not any(known_good_ending in domain for known_good_ending in ['.co.uk', '.com.au', '.ac.uk', '.gov.uk', '.org.uk']):
              simulated_content_description += " It uses multiple subdomains."
         if parsed_uri.scheme == 'http':
              simulated_content_description += " It uses insecure HTTP protocol."

    except Exception as e:
        print(f"Minor error analyzing URL structure for simulation: {e}")
    # --- End Simulation Logic ---

    # --- Tuned Prompt for URL Analysis ---
    prompt = f"""
    You are a cybersecurity analyst AI. Based *only* on the following URL structure and inferred context (do not attempt to visit the URL), assess its potential risk in a phishing scenario. Respond ONLY with a JSON object with the specified keys.

    URL for Analysis: "{url}"
    Inferred Context/Hints: "{simulated_content_description}"

    Required JSON Output Structure:
    {{
      "likely_content_type": "Infer likely page purpose based on URL (e.g., Credential Harvesting Page, Malware Delivery Vector, Legitimate Service Portal, Generic Landing Page, Marketing Page, Unknown).",
      "brand_impersonation_risk": "Assess likelihood of brand impersonation based *only* on URL structure (e.g., High - Typosquatting/Deceptive Domain, Medium - Contains Brand Name but not official, Low - Unrelated Domain/Known Good Domain, N/A).",
      "suspicious_url_patterns": ["List suspicious elements observed (e.g., Typosquatting Domain, Misleading Subdomain, Uncommon TLD, Multiple Subdomains, HTTP protocol, IP Address URL). **Do not list long paths or standard query parameters (like '/edit?usp=sharing') on known legitimate domains (like google.com) as inherently suspicious.**"],
      "overall_url_risk_assessment": "Assess the URL's risk level based *only* on its structure and the likely reputation of the domain. **Assign 'Low' risk if the domain is strongly associated with a known legitimate service (e.g., google.com, microsoft.com) unless other factors (like HTTP, clear typosquatting) are present.** (e.g., High, Medium, Low)."
    }}

    Analyze the URL structure, considering domain reputation context (treat known good domains as lower risk), and respond ONLY with the JSON object.
    """
    # --- End Tuned Prompt ---
    return _call_gemini_with_retry(prompt, expect_json=True)


def generate_alert_explanation(score, factors, attachment_info=None):
    """
    Generates a concise, human-readable alert explanation using Gemini.
    (Tuned Prompt for better grounding and tone)
    """
    if not gemini_model_initialized:
        return "Alert explanation generation failed: Gemini model not initialized."

    # --- Factors and Warning Formatting (Same as before) ---
    factors_summary = "\n".join([f"- {key}: {value}" for key, value in factors.items() if value and value != 'N/A'])

    attachment_warning = ""
    if attachment_info and attachment_info.get("found_suspicious"):
        suspicious_names = ", ".join(attachment_info.get("suspicious_files", []))
        attachment_warning = f"**Attachment Warning:** Suspicious file(s) detected: `{suspicious_names}`. These are high-risk and could contain malware. DO NOT OPEN."
    # --- End Formatting ---

    # --- Tuned Prompt for Explanation ---
    prompt = f"""
    Generate a concise, actionable security alert summary based *strictly* on the provided risk score and contributing factors. Tailor the explanation and recommendations to the actual risk level and detected issues. Avoid overly alarming language for lower risk scores.

    Risk Score: {score}/100
    Key Contributing Factors:
    {factors_summary if factors_summary else "- None significant"}
    {attachment_warning}

    Instructions:
    1. Start with a clear risk level statement reflecting the score:
        - Score 0-39: **Low Risk - Likely Safe**
        - Score 40-69: **Medium Risk - Caution Advised**
        - Score 70-89: **High Risk - Phishing/Malicious Attempt Likely**
        - Score 90-100: **Very High Risk - Malicious Intent Confirmed**
    2. Briefly explain the *specific* reasons listed in "Key Contributing Factors" (1-2 sentences). **Do not invent reasons not listed.** If factors are minor or relate to medium confidence findings, reflect that uncertainty.
    3. Include the attachment warning prominently if applicable.
    4. Recommend actions *appropriate* for the risk level and factors:
        - Low Risk: Usually "No immediate action needed, proceed with normal caution."
        - Medium Risk: "Review carefully. Verify link destinations before clicking. If unsure, verify with sender via another channel."
        - High/Very High Risk: "Delete immediately. Report as Phishing/Spam. Do not click links or open attachments."
    5. Keep the summary concise and professional (approx. 3-5 sentences).
    """
    # --- End Tuned Prompt ---

    result = _call_gemini_with_retry(prompt, expect_json=False)

    # Handle potential error response from retry function
    if isinstance(result, dict) and "error" in result:
        print(f"Error generating alert explanation (from retry func): {result['error']}")
        # Provide a more structured fallback based on score ranges
        if score >= 90: level, action = "Very High Risk", "Delete/Report Recommended."
        elif score >= 70: level, action = "High Risk", "Delete/Report Recommended."
        elif score >= 40: level, action = "Medium Risk", "Review Carefully/Verify."
        else: level, action = "Low Risk", "Likely Safe."
        attach_warn = " Check attachments carefully." if attachment_warning else ""
        return f"**{level} Alert** (Score: {score}/100). Risk detected based on factors like: {list(factors.keys())}.{attach_warn} {action} (AI Explanation Failed)"
    else:
        return result # Return the generated text explanation