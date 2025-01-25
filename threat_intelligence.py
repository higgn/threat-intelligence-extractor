import re
import spacy
import requests
import time
from typing import Dict, List, Any

# Load spaCy model for Named Entity Recognition (NER)
nlp = spacy.load("en_core_web_sm")

# VirusTotal API key (replace with your key)
VIRUSTOTAL_API_KEY = "6e6fda27e6ce7969aca5673503a6049a629709e3496fe9b096cc31a7de6f6922"

# MITRE ATT&CK mappings (simplified for this example)
MITRE_TACTICS = {
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Lateral Movement": "TA0008",
}

MITRE_TECHNIQUES = {
    "Spear Phishing Attachment": "T1566.001",
    "PowerShell": "T1059.001",
}

# Regex patterns for IoCs
IP_PATTERN = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
DOMAIN_PATTERN = r"\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
HASH_PATTERN = r"\b[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}\b"

def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extract Indicators of Compromise (IoCs) from the text.
    """
    iocs = {
        "IP addresses": re.findall(IP_PATTERN, text),
        "Domains": re.findall(DOMAIN_PATTERN, text),
        "Email addresses": re.findall(EMAIL_PATTERN, text),
        "File hashes": re.findall(HASH_PATTERN, text),
    }
    return iocs

def extract_ttps(text: str) -> Dict[str, List[Dict[str, str]]]:
    """
    Extract Tactics, Techniques, and Procedures (TTPs) from the text using MITRE ATT&CK.
    """
    tactics = []
    techniques = []

    # Check for tactics
    for tactic_name, tactic_id in MITRE_TACTICS.items():
        if tactic_name.lower() in text.lower():
            tactics.append({tactic_id: tactic_name})

    # Check for techniques
    for technique_name, technique_id in MITRE_TECHNIQUES.items():
        if technique_name.lower() in text.lower():
            techniques.append({technique_id: technique_name})

    return {"Tactics": tactics, "Techniques": techniques}

def extract_threat_actors(text: str) -> List[str]:
    """
    Extract threat actor names using spaCy NER.
    """
    doc = nlp(text)
    threat_actors = [ent.text for ent in doc.ents if ent.label_ == "ORG"]
    return threat_actors

def extract_targeted_entities(text: str) -> List[str]:
    """
    Extract targeted entities (industries or organizations) using spaCy NER.
    """
    doc = nlp(text)
    targeted_entities = [ent.text for ent in doc.ents if ent.label_ in ["ORG", "GPE"]]
    return targeted_entities

def enrich_malware_details(malware_name: str, file_hash: str = None) -> Dict[str, str]:
    """
    Enrich malware details using VirusTotal API.
    """
    if not VIRUSTOTAL_API_KEY:
        return {"Name": malware_name}

    # Add delay to respect VirusTotal API rate limits (4 requests per minute)
    time.sleep(15)

    if file_hash:
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    else:
        url = f"https://www.virustotal.com/api/v3/search?query={malware_name}"

    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        attributes = data.get("data", {}).get("attributes", {})
        return {
            "Name": malware_name,
            "md5": attributes.get("md5", "N/A"),
            "sha1": attributes.get("sha1", "N/A"),
            "sha256": attributes.get("sha256", "N/A"),
            "ssdeep": attributes.get("ssdeep", "N/A"),
            "TLSH": attributes.get("tlsh", "N/A"),
            "tags": ", ".join(attributes.get("tags", [])),
        }
    else:
        return {"Name": malware_name}

def extract_malware(text: str) -> List[Dict[str, str]]:
    """
    Extract malware details from the text.
    """
    malware_list = []
    doc = nlp(text)

    # Extract malware names and hashes
    malware_names = [ent.text for ent in doc.ents if ent.label_ == "PRODUCT"]
    file_hashes = re.findall(HASH_PATTERN, text)

    for malware_name in malware_names:
        malware_details = enrich_malware_details(malware_name)
        malware_list.append(malware_details)

    for file_hash in file_hashes:
        malware_details = enrich_malware_details("Unknown", file_hash)
        malware_list.append(malware_details)

    return malware_list

def extract_threat_intelligence(report_text: str) -> Dict[str, Any]:
    """
    Extract all threat intelligence data from the report.
    """
    threat_intel = {
        "IoCs": extract_iocs(report_text),
        "TTPs": extract_ttps(report_text),
        "Threat Actor(s)": extract_threat_actors(report_text),
        "Malware": extract_malware(report_text),
        "Targeted Entities": extract_targeted_entities(report_text),
    }
    return threat_intel

# Example Input
report_text = """
The APT33 group, suspected to be from Iran, has launched a new campaign targeting
the energy sector organizations. The attack utilizes Shamoon malware, known for its
destructive capabilities. The threat actor exploited a vulnerability in the network
perimeter to gain initial access. The malware was delivered via spear-phishing emails
containing a malicious attachment. The malware's behavior was observed communicating
with IP address 192.168.1.1 and domain example.com. The attack also involved lateral
movement using PowerShell scripts.
"""

# Extract Threat Intelligence
threat_intel = extract_threat_intelligence(report_text)

# Print Output
import pprint
pprint.pprint(threat_intel)
