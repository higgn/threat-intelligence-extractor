import re
import spacy
import requests
import pdfplumber
import streamlit as st
import pandas as pd
import plotly.express as px
import logging
import json
from typing import Dict, List, Any
from PIL import Image
import io

# Load spaCy model for Named Entity Recognition (NER)
nlp = spacy.load("en_core_web_sm")

# VirusTotal API key (replace with your key)
VIRUSTOTAL_API_KEY = "6e6fda27e6ce7969aca5673503a6049a629709e3496fe9b096cc31a7de6f6922"

# MITRE ATT&CK mappings (expanded for this example)
MITRE_TACTICS = {
    "Initial Access": "TA0001",
    "Execution": "TA0002",
    "Persistence": "TA0003",
    "Privilege Escalation": "TA0004",
    "Defense Evasion": "TA0005",
    "Credential Access": "TA0006",
    "Discovery": "TA0007",
    "Lateral Movement": "TA0008",
    "Collection": "TA0009",
    "Exfiltration": "TA0010",
    "Command and Control": "TA0011",
    "Impact": "TA0040",
}

MITRE_TECHNIQUES = {
    "Spear Phishing Attachment": "T1566.001",
    "PowerShell": "T1059.001",
    "Exploitation for Client Execution": "T1203",
    "BYOVD": "T1068",
    "Anti-Forensics": "T1070",
    "Scheduled Task/Job": "T1053",
    "Registry Run Keys / Startup Folder": "T1547.001",
    "Process Injection": "T1055",
    "Obfuscated Files or Information": "T1027",
    "Data Encrypted for Impact": "T1486",
}

# Regex patterns for IoCs
IP_PATTERN = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
DOMAIN_PATTERN = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
EMAIL_PATTERN = r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
HASH_PATTERN = r"\b[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64}\b"

# Blacklist of system file extensions
SYSTEM_FILE_EXTENSIONS = [".dll", ".exe", ".log", ".sys", ".tmp", ".dat", ".pf", ".php", ".evtx", ".tlb"]

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Streamlit App Title
st.title("Threat Intelligence Extractor")
st.markdown("Upload a cybersecurity report (PDF) or paste the text to extract threat intelligence.")

# File Uploader
uploaded_file = st.file_uploader("Choose a PDF file", type="pdf")

# Text Input Box for Copy-Pasting Reports
st.subheader("OR Paste Report Text Below")
report_text_input = st.text_area("Paste your threat report here")

# Multi-select widget for customizable outputs
st.subheader("Customize Output")
selected_fields = st.multiselect(
    "Select fields to extract:",
    ["IoCs", "TTPs", "Threat Actor(s)", "Malware", "Targeted Entities", "Images"],
    default=["IoCs", "TTPs", "Threat Actor(s)", "Malware", "Targeted Entities", "Images"]
)

def extract_text_from_pdf(pdf_file) -> str:
    """
    Extract text from an uploaded PDF file.
    """
    text = ""
    try:
        with pdfplumber.open(pdf_file) as pdf:
            for page in pdf.pages:
                text += page.extract_text()
    except Exception as e:
        st.error(f"Error reading PDF file: {e}")
    return text

def extract_images_from_pdf(pdf_file) -> List[Image.Image]:
    """
    Extract images from an uploaded PDF file.
    """
    images = []
    try:
        with pdfplumber.open(pdf_file) as pdf:
            for page in pdf.pages:
                for img in page.images:
                    img_data = img["stream"].get_data()
                    images.append(Image.open(io.BytesIO(img_data)))
    except Exception as e:
        st.error(f"Error extracting images from PDF: {e}")
    return images

def extract_iocs(text: str) -> Dict[str, List[str]]:
    """
    Extract Indicators of Compromise (IoCs) from the text.
    """
    iocs = {
        "IP addresses": list(set(re.findall(IP_PATTERN, text))),
        "Domains": list(set([domain for domain in re.findall(DOMAIN_PATTERN, text) 
                            if not any(ext in domain for ext in SYSTEM_FILE_EXTENSIONS) 
                            and not domain.lower() in ["response.content", "response.content;"]])),
        "Email addresses": list(set(re.findall(EMAIL_PATTERN, text))),
        "File hashes": list(set(re.findall(HASH_PATTERN, text))),
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
    threat_actors = list(set([ent.text for ent in doc.ents if ent.label_ == "ORG" 
                             and ent.text.lower() not in ["ip", "c2", "powershell", "dll", "anydesk", 
                                                          "microsoft", "google", "c:\\programdata\\", "appcrash", 
                                                          "symantec protection bulletin", "vps", "ioc", "wmi", "c&c", 
                                                          "invoke-webrequest", "jabswitch.exe", "symantec endpoint", 
                                                          "jumpcloud", "45.67.230[.]91", "powershell - seedworm"]]))
    return threat_actors

def extract_targeted_entities(text: str) -> List[str]:
    """
    Extract targeted entities (industries or organizations) using spaCy NER.
    """
    doc = nlp(text)
    targeted_entities = list(set([ent.text for ent in doc.ents if ent.label_ in ["ORG", "GPE"] 
                                 and ent.text.lower() not in ["ip", "c2", "powershell", "dll", "anydesk", 
                                                              "microsoft", "c:\\programdata\\", "appcrash", 
                                                              "symantec protection bulletin", "vps", "ioc", "wmi", "c&c", 
                                                              "invoke-webrequest", "jabswitch.exe", "symantec endpoint", 
                                                              "jumpcloud", "45.67.230[.]91", "powershell - seedworm"]]))
    return targeted_entities

def enrich_malware_with_virustotal(file_hash: str) -> Dict[str, str]:
    """
    Enrich malware details using VirusTotal API.
    """
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an exception for HTTP errors
        data = response.json()
        return {
            "md5": data.get("md5", ""),
            "sha1": data.get("sha1", ""),
            "sha256": data.get("sha256", ""),
            "ssdeep": data.get("ssdeep", ""),
            "TLSH": data.get("tlsh", ""),
            "tags": data.get("tags", []),
        }
    except requests.exceptions.RequestException as e:
        logging.error(f"Error querying VirusTotal for hash {file_hash}: {e}")
        return {}

def extract_malware(text: str) -> List[Dict[str, str]]:
    """
    Extract malware details from the text and enrich with VirusTotal data.
    """
    malware_list = []
    doc = nlp(text)

    # Extract potential malware names using NER and keywords
    malware_keywords = ["malware", "trojan", "worm", "ransomware", "spyware", "backdoor", "rootkit"]
    malware_names = list(set([ent.text for ent in doc.ents if ent.label_ == "PRODUCT" 
                             and any(keyword in ent.text.lower() for keyword in malware_keywords)]))

    # Extract file hashes
    file_hashes = re.findall(HASH_PATTERN, text)

    # Add malware names to the list
    for malware_name in malware_names:
        malware_list.append({"Name": malware_name})

    # Add file hashes to the list
    for file_hash in file_hashes:
        malware_details = {"Name": "Unknown", "Hash": file_hash}
        malware_details.update(enrich_malware_with_virustotal(file_hash))
        malware_list.append(malware_details)

    return malware_list

def extract_threat_intelligence(report_text: str) -> Dict[str, Any]:
    """
    Extract all threat intelligence data from the report.
    """
    threat_intel = {
        "IoCs": extract_iocs(report_text) if "IoCs" in selected_fields else {},
        "TTPs": extract_ttps(report_text) if "TTPs" in selected_fields else {},
        "Threat Actor(s)": extract_threat_actors(report_text) if "Threat Actor(s)" in selected_fields else [],
        "Malware": extract_malware(report_text) if "Malware" in selected_fields else [],
        "Targeted Entities": extract_targeted_entities(report_text) if "Targeted Entities" in selected_fields else [],
    }
    return threat_intel

# Streamlit UI Logic
if uploaded_file is not None:
    # Extract text from the uploaded PDF
    report_text = extract_text_from_pdf(uploaded_file)
    # Extract images from the uploaded PDF
    images = extract_images_from_pdf(uploaded_file) if "Images" in selected_fields else []
elif report_text_input:
    report_text = report_text_input
    images = []
else:
    st.warning("🙂‍↕️ Hi, Please upload a PDF file or paste the report text to get started.")
    st.stop()

if report_text:
    # Extract threat intelligence
    threat_intel = extract_threat_intelligence(report_text)

    # Display results in Streamlit
    st.subheader("Extracted Threat Intelligence")
    st.json(threat_intel)

    # Visualize IoCs
    if "IoCs" in selected_fields:
        st.subheader("Indicators of Compromise (IoCs)")
        ioc_data = {
            "Type": ["IP Addresses", "Domains", "Email Addresses", "File Hashes"],
            "Count": [
                len(threat_intel["IoCs"].get("IP addresses", [])),
                len(threat_intel["IoCs"].get("Domains", [])),
                len(threat_intel["IoCs"].get("Email addresses", [])),
                len(threat_intel["IoCs"].get("File hashes", [])),
            ],
        }
        df = pd.DataFrame(ioc_data)
        fig = px.bar(df, x="Type", y="Count", title="IoCs by Type")
        st.plotly_chart(fig)

    # Visualize TTPs
    if "TTPs" in selected_fields:
        st.subheader("Tactics, Techniques, and Procedures (TTPs)")
        st.write("Tactics:", threat_intel["TTPs"].get("Tactics", []))
        st.write("Techniques:", threat_intel["TTPs"].get("Techniques", []))

    # Visualize Threat Actors
    if "Threat Actor(s)" in selected_fields:
        st.subheader("Threat Actor(s)")
        st.write(threat_intel.get("Threat Actor(s)", []))

    # Visualize Malware
    if "Malware" in selected_fields:
        st.subheader("Malware Details")
        st.write(threat_intel.get("Malware", []))

    # Visualize Targeted Entities
    if "Targeted Entities" in selected_fields:
        st.subheader("Targeted Entities")
        st.write(threat_intel.get("Targeted Entities", []))

    # Visualize Images
    if "Images" in selected_fields and images:
        st.subheader("Extracted Images")
        for img in images:
            st.image(img, caption="Extracted Image", use_column_width=True)

    # Summary Section
    st.subheader("Summary")
    st.write(f"**Total IoCs Extracted:** {len(threat_intel.get('IoCs', {}).get('IP addresses', [])) + len(threat_intel.get('IoCs', {}).get('Domains', [])) + len(threat_intel.get('IoCs', {}).get('Email addresses', [])) + len(threat_intel.get('IoCs', {}).get('File hashes', []))}")
    st.write(f"**Total TTPs Identified:** {len(threat_intel.get('TTPs', {}).get('Tactics', [])) + len(threat_intel.get('TTPs', {}).get('Techniques', []))}")
    st.write(f"**Total Threat Actors Identified:** {len(threat_intel.get('Threat Actor(s)', []))}")
    st.write(f"**Total Malware Identified:** {len(threat_intel.get('Malware', []))}")
    st.write(f"**Total Targeted Entities Identified:** {len(threat_intel.get('Targeted Entities', []))}")
    st.write(f"**Total Images Extracted:** {len(images)}")

    # Download Button
    st.subheader("Download Results")
    st.download_button(
        label="Download Threat Intelligence as JSON",
        data=json.dumps(threat_intel, indent=4),
        file_name="threat_intelligence.json",
        mime="application/json",
    )
else:
    st.error("Failed to extract text from the PDF file.")
