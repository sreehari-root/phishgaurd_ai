import regex as re # Use the 'regex' library for better Unicode handling
import email # Python's built-in email parsing library
from email import policy
from datetime import datetime # Added for timestamping

def extract_urls(text):
    """
    Extracts URLs from a given text using a robust regex pattern.
    Handles various URL schemes and international characters.
    """
    if not text:
        return []
    # Enhanced regex to find URLs (including http, https, ftp, file)
    # Accounts for parentheses, common characters in paths/queries.
    try:
        # A simplified but common pattern - might need refinement for edge cases
        url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+' \
                      r'[\w\-\._~:/?#[\]@!\$&\'\(\)\*\+,;=.]+'
        # Using re.UNICODE flag might help with international domains if needed
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        # Basic cleanup: remove trailing punctuation if accidentally included
        cleaned_urls = [re.sub(r'[.,!?:;)\s]+$', '', url) for url in urls]
        # Further cleanup: Remove trailing > if from HTML parsing leftovers
        cleaned_urls = [url[:-1] if url.endswith('>') else url for url in cleaned_urls]
        return list(set(cleaned_urls)) # Return unique URLs
    except Exception as e:
        print(f"Error extracting URLs: {e}")
        return []

def generate_sample_input(type="phishing_subtle"):
    """Generates sample email/message data for testing."""
    if type == "phishing_urgent":
        return {
            "sender": "security@paypa1.com",
            "subject": "Urgent: Action Required - Unusual Activity Detected",
            "body": "Dear Customer,\n\nWe detected unusual login activity on your PayPal account. For your security, please verify your identity immediately by clicking here: http://paypa1.com/verify-login\n\nFailure to do so within 2 hours may result in account suspension.\n\nThanks,\nPayPal Security Team"
        }
    elif type == "social_eng_ceo":
         return {
            "sender": "ceo@mycompany.com", # Maybe a spoofed version in reality
            "subject": "Urgent Request - Need your help",
            "body": "Hi [Your Name],\n\nI'm stuck in meetings all day but need you to urgently purchase 5x $100 Amazon gift cards for a client presentation. Please scratch off the codes and email them to me directly ASAP. I'll reimburse you tomorrow.\n\nNeeds to be done in the next 30 minutes.\n\nThanks,\n[CEO's Name]\nSent from my iPhone"
         }
    elif type == "benign":
         return {
            "sender": "newsletter@trustednews.com",
            "subject": "Your Weekly Tech Roundup",
            "body": "Hello,\n\nHere's your weekly summary of the latest in tech. Read about the new advancements in AI processing and the latest gadget reviews.\n\nVisit our site for more: https://trustednews.com/latest\n\nHave a great week!"
         }
    else: # Default subtle phishing
        return {
            "sender": "support@microsft-live.com",
            "subject": "Account Storage Limit Reached",
            "body": "Dear User,\n\nYour Microsoft account storage is almost full. To avoid service disruption, please upgrade your storage plan.\n\nClick here to view options: http://microsft-live.com/user/upgrade?id=12345\n\nThank you,\nMicrosoft Support"
        }

def extract_basic_headers(raw_email_source):
    """Parses raw email source and extracts basic headers."""
    headers = {}
    body = "" # Initialize body
    if not raw_email_source:
        return headers, "No source provided"

    try:
        msg = email.message_from_string(raw_email_source, policy=policy.default)
        # Extract common and useful headers
        header_keys = ['Subject', 'From', 'To', 'Date', 'Return-Path', 'Reply-To', 'Message-ID']
        for key in header_keys:
             headers[key] = msg.get(key, None) # Use None if header missing

        # Get potentially multiple Received headers (usually reverse order)
        received_headers = msg.get_all('Received', failobj=[])
        if received_headers:
             headers['Received_First'] = received_headers[0] # Usually the last hop
             # headers['Received_All'] = received_headers # Optionally store all

        # Extract Authentication Results if present (useful!)
        headers['Authentication-Results'] = msg.get('Authentication-Results', None)

        body = extract_email_body(msg) # Call body extraction function

        # Clean None values
        headers = {k: v for k, v in headers.items() if v is not None}

        return headers, body
    except Exception as e:
        print(f"Error parsing email headers: {e}")
        # Return error within headers dict?
        return {"Error": f"Could not parse headers: {e}"}, "[Header parsing failed]"


def extract_email_body(msg):
    """Extracts the text body from an email.message object."""
    body = ""
    if msg.is_multipart():
        # Prioritize text/plain over text/html
        plain_part = None
        html_part = None
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get('Content-Disposition'))
            if 'attachment' in content_disposition:
                continue # Skip attachments

            if content_type == 'text/plain' and plain_part is None:
                plain_part = part
            elif content_type == 'text/html' and html_part is None:
                html_part = part

        target_part = plain_part if plain_part else html_part

        if target_part:
            try:
                payload = target_part.get_payload(decode=True)
                charset = target_part.get_content_charset() or 'utf-8' # Default to utf-8
                body = payload.decode(charset, errors='replace')
                # If we used HTML, try basic cleaning
                if target_part == html_part and plain_part is None:
                     body = re.sub('<style.*?</style>', '', body, flags=re.DOTALL | re.IGNORECASE) # Remove style blocks
                     body = re.sub('<script.*?</script>', '', body, flags=re.DOTALL | re.IGNORECASE) # Remove script blocks
                     body = re.sub('<[^>]*>', '', body) # Basic tag stripping
                     body = re.sub(r'\s+', ' ', body).strip() # Clean up whitespace
                     # Consider using html.unescape for entities like  
                     import html
                     body = html.unescape(body)

            except Exception as e:
                print(f"Could not decode part with charset {target_part.get_content_charset()}: {e}")
                body = "[Could not decode body part]"
        else:
             body = "[No suitable text/plain or text/html body part found]"

    else:
        # Not multipart, handle plain text or html directly
        content_type = msg.get_content_type()
        if content_type in ['text/plain', 'text/html']:
            try:
                payload = msg.get_payload(decode=True)
                charset = msg.get_content_charset() or 'utf-8'
                body = payload.decode(charset, errors='replace')
                if content_type == 'text/html':
                     body = re.sub('<style.*?</style>', '', body, flags=re.DOTALL | re.IGNORECASE)
                     body = re.sub('<script.*?</script>', '', body, flags=re.DOTALL | re.IGNORECASE)
                     body = re.sub('<[^>]*>', '', body)
                     body = re.sub(r'\s+', ' ', body).strip()
                     import html
                     body = html.unescape(body)
            except Exception as e:
                print(f"Could not decode single part message: {e}")
                body = "[Could not decode message body]"
        else:
            body = "[Body is not plain text or HTML]"

    return body.strip() if body else "[No readable text body found]"


def extract_attachment_names(raw_email_source):
    """Parses raw email source and extracts attachment filenames."""
    attachment_names = []
    if not raw_email_source:
        return attachment_names
    try:
        msg = email.message_from_string(raw_email_source, policy=policy.default)
        if msg.is_multipart():
            for part in msg.walk():
                # Check if part is an attachment using Content-Disposition
                content_disposition = str(part.get('Content-Disposition'))
                if 'attachment' in content_disposition.lower():
                    filename = part.get_filename()
                    if filename: # If filename exists, it's likely an attachment
                        attachment_names.append(filename)
        # Check for non-multipart messages that might be attachments (less common)
        elif 'attachment' in str(msg.get('Content-Disposition')).lower():
             filename = msg.get_filename()
             if filename:
                 attachment_names.append(filename)

    except Exception as e:
        print(f"Error parsing attachments: {e}")
    return list(set(attachment_names)) # Return unique names

def check_suspicious_attachment_names(attachment_names):
    """Checks a list of filenames for suspicious patterns."""
    suspicious_files = []
    # Expanded list of suspicious patterns
    suspicious_patterns = [
        r'\.(exe|pif|application|gadget|msi|msp|com|scr|hta|cpl|msc|jar)$', # Definite executables
        r'\.(bat|cmd|vb|vbs|vbe|js|jse|ps1|ps1xml|ps2|ps2xml|psc1|psc2|ws|wsf|wsh)$', # Scripts
        r'\.(reg)$', # Registry files
        r'\.(lnk)$', # Shortcuts (can point to malicious things)
        r'\.(iso|img|udf)$', # Disk images (used to bypass MOTW)
        r'\.(docm|dotm|xlsm|xltm|xlam|pptm|potm|ppam|sldm)$', # Macro-enabled Office
        r'\.(pdf|docx?|xlsx?|pptx?)\.(exe|js|bat|vbs|scr)$', # Double extensions hiding executable
        r'^(invoice|payment|receipt|scan|document|form|resume|urgent|important).*\.(js|exe|vbs|bat|scr|zip|rar|iso)$', # Common lure names + risky extension
        r'.*\.zip$', r'.*\.rar$', r'.*\.7z$', r'.*\.ace$', r'.*\.arj$', # Archives can hide malware
    ]
    if not attachment_names:
        return suspicious_files, False

    found_suspicious = False
    for name in attachment_names:
        for pattern in suspicious_patterns:
            if re.search(pattern, name, re.IGNORECASE):
                if name not in suspicious_files: # Avoid duplicates
                    suspicious_files.append(name)
                found_suspicious = True
                break # Found one pattern for this file, move to next file
    return suspicious_files, found_suspicious