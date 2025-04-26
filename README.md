# PhishGuard AI Sentinel ++

## Overview

PhishGuard AI Sentinel ++ is an enhanced intelligent system developed for the CloudSEK AI in Cybersecurity Hackathon, addressing **Category #2: Phishing and Social Engineering Defense**. This tool analyzes email or message content using Google's Gemini AI to detect sophisticated phishing attempts, social engineering tactics, and other suspicious indicators that might bypass traditional filters.

It moves beyond simple keyword matching by understanding context, sender intent, linguistic patterns, header information (when provided), attachment risks, and potential psychological manipulation. The system provides a calculated risk score and a clear, AI-generated explanation of potential threats, tuned to reduce false positives on legitimate communications.

## Enhanced Features (v2)

*   **AI-Powered Deep Analysis:** Uses Google Gemini API (gemini-1.5-flash) to analyze text content for:
    *   Intent & Urgency (Differentiating standard deadlines from high-pressure tactics)
    *   Tone & Sentiment
    *   Brand/Individual Impersonation Signals (Tuned to avoid flagging standard signatures excessively)
    *   Psychological Tactics (Focusing on clearly manipulative tactics)
    *   Linguistic Anomalies
*   **Multiple Input Modes:**
    *   **Manual Input:** Analyze sender, subject, and body text entered directly.
    *   **Raw Email Source Analysis:** Paste the full raw source of an email (including headers) for more comprehensive analysis.
*   **Basic Header Parsing & AI Context:** When raw source is provided, extracts key headers (From, To, Subject, Auth-Results, Received etc.) and includes them as context for the AI analysis, checking for inconsistencies.
*   **Attachment Name Analysis:** Extracts attachment filenames (from raw source only) and flags potentially suspicious names/extensions (e.g., `.exe`, `.js`, double extensions, lure names).
*   **URL Analysis (Blocklist & Simulated AI):**
    *   Checks extracted URLs against a configurable static blocklist.
    *   Uses Gemini to *simulate* analysis of URL landing page content based on URL patterns, **tuned to be less suspicious of long paths on known legitimate domains** (e.g., google.com, microsoft.com).
*   **Contextual Risk Scoring:** Calculates a score (0-100) based on dynamically weighted factors from AI analysis (text, headers, URL), attachment checks, and blocklist results. Weights are tuned to balance sensitivity and false positives.
*   **Explainable AI Alerts:** Generates clear, concise natural language summaries using Gemini, explaining *why* a message is flagged and tailoring recommendations to the specific risk level and findings.
*   **Interactive Web UI:** Built with Streamlit, featuring:
    *   Tabs for different input methods.
    *   Clear display of risk score, explanation, and contributing factors.
    *   Detailed analysis breakdown section.
    *   Session history for recent analyses.
    *   Export functionality for the analysis summary.
*   **False Positive Reduction:** Specific tuning applied to AI prompts and scoring logic to better distinguish legitimate business communication from threats.

## Tech Stack

*   **Language:** Python 3.9+
*   **AI Model:** Google Gemini API (gemini-1.5-flash via `google-generativeai` SDK)
*   **Web Framework:** Streamlit
*   **Core Libraries:**
    *   `python-dotenv` (API key management)
    *   `regex` (URL extraction)
    *   `pandas` (Displaying parsed headers)
    *   `email` (Built-in library for parsing raw email source)
*   **Environment:** Developed on Windows (instructions below), cross-platform compatible.

## Setup Instructions

1.  **Clone Repository / Download Code:** Obtain the project files.
    ```bash
    # If using Git
    git clone <your-repo-url>
    cd phishguard-ai
    ```

2.  **Install Python:** Ensure Python 3.8+ is installed and added to your PATH.

3.  **Create Virtual Environment (Recommended):**
    ```bash
    # In the project root directory (phishguard_ai/)
    python -m venv venv
    # Activate (Windows)
    .\venv\Scripts\activate
    # Activate (Linux/macOS)
    # source venv/bin/activate
    ```

4.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

5.  **Set Up API Key:**
    *   Create a file named `.env` in the project root directory.
    *   Get your API key from [Google AI Studio](https://aistudio.google.com/app/apikey).
    *   Add the following line to `.env`, replacing the placeholder:
        ```dotenv
        GOOGLE_API_KEY="YOUR_GEMINI_API_KEY_HERE"
        ```
    *   The `.gitignore` file prevents committing this file. Keep your key secure!

## Running the Application

1.  Ensure your virtual environment is active (`(venv)` prefix in prompt).
2.  Navigate to the project root directory (`phishguard_ai/`).
3.  Run the Streamlit app:
    ```bash
    streamlit run app.py
    ```
4.  The application interface will open in your default web browser.
5.  Use the **radio buttons** at the top to select "Manual Input" or "Paste Raw Email Source".
    *   **Manual Input:** Enter Sender, Subject, Body. Use sample buttons for quick tests.
    *   **Paste Raw Email Source:** Paste the entire email source (including all headers starting typically with `Return-Path:` or `Received:`). The tool will parse headers, body, and attachments.

## Folder Structure

```
phishguard_ai/
│
├── data/
│   └── url_blocklist.txt         # Simple blocklist of malicious domains
│
├── src/
│   ├── __init__.py             # Makes 'src' a Python package
│   ├── basic_checks.py       # Non-AI checks (blocklist, simulated sender)
│   ├── core_analyzer.py      # Orchestrates analysis, calculates score
│   ├── gemini_handler.py     # Handles all Gemini API interactions & prompts
│   └── utils.py              # Utility functions (URL extraction, samples)
│
├── venv/                       # Python virtual environment (if created)
│
├── .env                        # Stores API key (DO NOT COMMIT)
├── .gitignore                  # Specifies intentionally untracked files for Git
├── app.py                      # Main Streamlit application file
├── README.md                   # This file
└── requirements.txt            # Project dependencies
```


## Hackathon Deliverables Checklist Fulfillment

*   **1. Prototype:** Running `streamlit run app.py` launches the functional demo showcasing core features (AI analysis, multiple inputs, risk scoring, explanations, history, export).
*   **2. Source Code:** The code in this repository (`app.py`, `src/` modules) is the source code. It includes comments explaining key sections. *(**Action Required:** You need to host this on a public GitHub repository).*
*   **3. Documentation:** A separate 2-3 page document needs to be created covering the points below. *(**Action Required:** See guidance below to create this document).*
*   **4. Presentation:** A separate 5-7 minute slide deck (PDF) needs to be created. *(**Action Required:** See guidance below for slide content).*

## Limitations & Future Work

*   **Simulation:** URL content analysis is simulated based on patterns, not live fetching. Sender checks in Manual Mode are basic simulations.
*   **Blocklist:** Uses a static file; real systems need dynamic threat intelligence feeds.
*   **Parsing:** Email parsing handles common cases but might struggle with highly complex/malformed emails. HTML-to-text conversion is basic.
*   **Tuning:** AI prompt tuning and scoring weights are iterative; further refinement with larger datasets would improve accuracy and reduce edge-case false positives/negatives.
*   **Scalability:** Designed as a prototype; high-volume processing requires asynchronous architecture.

**Future Enhancements:**
*   Integrate real-time CTI feeds (e.g., VirusTotal, PhishTank API).
*   Implement safe URL sandboxing (e.g., using services or isolated browsers).
*   Direct email integration via OAuth/APIs (Gmail, Microsoft Graph) for automated scanning.
*   Attachment sandboxing and deeper analysis (beyond filename).
*   User feedback mechanism for continuous learning/tuning.
*   More sophisticated header analysis (DMARC alignment, path analysis).
*   Dashboard with historical trends and analytics.

## Tuning Note

Achieving the right balance between detecting threats and avoiding false positives with AI requires careful prompt engineering and scoring weight adjustments. This prototype has undergone initial tuning, but continuous evaluation and refinement are essential for real-world deployment.