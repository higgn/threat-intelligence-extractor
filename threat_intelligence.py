import re
import spacy
import requests
import time
import pdfplumber
import streamlit as st
from typing import Dict, List, Any
from streamlit.runtime.uploaded_file_manager import UploadedFile

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

# Streamlit App Title
st.title("Threat Intelligence Extractor")
st.markdown("Upload a cybersecurity report (PDF) to extract threat intelligence.")

# File Uploader
uploaded_file = st.file_uploader("Choose a PDF file", type="pdf")

def extract_text_from_pdf(pdf_file: UploadedFile) -> str:
    """
    Extract text from an uploaded PDF file.
    """
    text = ""
    with pdfplumber.open(pdf_file) as pdf:
        for page in pdf.pages:
            text += page.extract_text()
    return text

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

    # List of known malware names (can be expanded)
    known_malware = ["Shamoon", "WannaCry", "Stuxnet", "NotPetya", "HrServ", "Headlace"]

    # Extract malware names
    malware_names = []
    for token in doc:
        if token.text in known_malware:
            malware_names.append(token.text)

    # Extract file hashes
    file_hashes = re.findall(HASH_PATTERN, text)

    # Enrich malware details
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

# Streamlit UI Logic
if uploaded_file is not None:
    # Extract text from the uploaded PDF
    report_text = extract_text_from_pdf(uploaded_file)

    # Extract threat intelligence
    threat_intel = extract_threat_intelligence(report_text)

    # Display results in Streamlit
    st.subheader("Extracted Threat Intelligence")
    st.json(threat_intel)

    # Visualize IoCs
    st.subheader("Indicators of Compromise (IoCs)")
    st.write("IP Addresses:", threat_intel["IoCs"]["IP addresses"])
    st.write("Domains:", threat_intel["IoCs"]["Domains"])
    st.write("Email Addresses:", threat_intel["IoCs"]["Email addresses"])
    st.write("File Hashes:", threat_intel["IoCs"]["File hashes"])

    # Visualize TTPs
    st.subheader("Tactics, Techniques, and Procedures (TTPs)")
    st.write("Tactics:", threat_intel["TTPs"]["Tactics"])
    st.write("Techniques:", threat_intel["TTPs"]["Techniques"])

    # Visualize Threat Actors
    st.subheader("Threat Actor(s)")
    st.write(threat_intel["Threat Actor(s)"])

    # Visualize Malware
    st.subheader("Malware Details")
    st.write(threat_intel["Malware"])

    # Visualize Targeted Entities
    st.subheader("Targeted Entities")
    st.write(threat_intel["Targeted Entities"])
else:
    st.warning("Please upload a PDF file to get started.")
