import os
import urllib.parse
import random # Added for simulate_sender_checks

# Define path relative to this file's location
BLOCKLIST_PATH = os.path.join(os.path.dirname(__file__), '..', 'data', 'url_blocklist.txt')

def load_blocklist(filepath=BLOCKLIST_PATH):
    """Loads the URL blocklist from a file."""
    blockset = set() # Initialize blockset
    try:
        with open(filepath, 'r') as f:
            # Read lines, strip whitespace, ignore empty lines and comments
            for line in f:
                 entry = line.strip().lower()
                 if entry and not entry.startswith('#'):
                      if '://' in entry: # Assume it's a full URL
                           try:
                                parsed = urllib.parse.urlparse(entry)
                                domain = parsed.netloc
                                if domain.startswith('www.'): domain = domain[4:]
                                if domain: blockset.add(domain) # Add domain from URL
                                blockset.add(entry) # Add full URL as well
                           except Exception:
                                print(f"Warning: Could not parse URL in blocklist: {entry}")
                      else: # Assume it's a domain
                           if entry.startswith('www.'): entry = entry[4:]
                           if entry: blockset.add(entry) # Add non-empty domain
            return blockset
    except FileNotFoundError:
        print(f"Warning: Blocklist file not found at {filepath}. Blocklist will be empty.")
        return set()
    except Exception as e:
        print(f"Error loading blocklist: {e}")
        return set()

# Load the blocklist when the module is imported
url_blocklist = load_blocklist()
if url_blocklist: # Only print if loaded successfully
    print(f"Loaded {len(url_blocklist)} domains/URLs into blocklist.")

def check_url_blocklist(url):
    """Checks if the URL or its domain is in the blocklist."""
    if not url or not url_blocklist:
        return False
    try:
        url_lower = url.lower()
        # Check full URL first
        if url_lower in url_blocklist:
            return True

        # Extract domain name
        parsed_url = urllib.parse.urlparse(url_lower)
        domain = parsed_url.netloc
        # Remove www. prefix if present for matching
        if domain.startswith('www.'):
            domain = domain[4:]

        # Check if the domain is blocklisted
        if domain in url_blocklist:
            return True

    except Exception as e:
        print(f"Error parsing or checking URL '{url}': {e}")
    return False

# Ensure this function exists and is spelled correctly
def simulate_sender_checks(sender_email):
    """
    Simulates basic sender verification checks (SPF/DKIM) ONLY for manual mode.
    This is a placeholder and not reliable. Header analysis is preferred.
    """
    # Extremely basic simulation based on domain name patterns
    if not sender_email or '@' not in sender_email:
        return {"spf": "fail", "dkim": "fail", "reason": "Invalid sender format (Simulated)"}

    domain = sender_email.split('@')[1].lower()

    # Simulate common phishing domain patterns failing checks
    # Added more patterns
    suspicious_patterns = ["paypa1", "microsft", "support-", "-login", ".xyz", ".org", ".net", "secure-", "update-", "-verify", "service."]
    is_suspicious = any(pattern in domain for pattern in suspicious_patterns)
    # Avoid flagging common legit domains even if they contain parts of patterns
    known_good_domains = ["microsoft.com", "paypal.com", "google.com", "apple.com", "outlook.com", "trustednews.com"]
    is_known_good = any(kgd in domain for kgd in known_good_domains)

    if is_suspicious and not is_known_good:
         # Higher chance of simulated failure for suspicious domains
         if random.random() < 0.75: # 75% chance of failing
             spf_res = "fail" if random.random() < 0.8 else "softfail"
             dkim_res = "fail" if random.random() < 0.8 else "temperror"
             return {"spf": spf_res, "dkim": dkim_res, "reason": "Simulated failure for suspicious domain pattern"}

    # Simulate general possibility of failure for other domains
    spf_pass = random.random() > 0.1 # 90% chance pass
    dkim_pass = random.random() > 0.15 # 85% chance pass

    if spf_pass and dkim_pass:
         return {"spf": "pass", "dkim": "pass", "reason": "Simulated pass"}
    elif spf_pass:
         return {"spf": "pass", "dkim": "fail", "reason": "Simulated DKIM failure"}
    elif dkim_pass:
         return {"spf": "fail", "dkim": "pass", "reason": "Simulated SPF failure"}
    else:
         return {"spf": "fail", "dkim": "fail", "reason": "Simulated SPF and DKIM failure"}