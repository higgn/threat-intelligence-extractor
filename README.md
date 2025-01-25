# Threat Intelligence Extractor

A Python tool to extract threat intelligence from cybersecurity reports using **Natural Language Processing (NLP)** and the **VirusTotal API**. This tool automatically extracts:
- **Indicators of Compromise (IoCs)**: IP addresses, domains, file hashes, and email addresses.
- **Tactics, Techniques, and Procedures (TTPs)**: Mapped to the MITRE ATT&CK framework.
- **Threat Actors**: Names of threat actor groups or individuals.
- **Malware**: Details enriched using the VirusTotal API.
- **Targeted Entities**: Organizations or industries targeted in the attack.

---

## **Features**
- **Regex-based IoC Extraction**: Extracts IPs, domains, emails, and file hashes.
- **spaCy NER**: Detects threat actors and targeted entities.
- **MITRE ATT&CK Mapping**: Maps tactics and techniques to the MITRE framework.
- **VirusTotal API Integration**: Enriches malware details with hashes, tags, and more.
- **Structured Output**: Returns results in a clean, JSON-like dictionary format.

---

## **Requirements**
- Python 3.8+
- Libraries: `spacy`, `requests`
- VirusTotal API key (free tier available)

---

## **Installation**
1. Clone the repository:
   ```bash
   git clone https://github.com/higgn/threat-intelligence-extractor.git
   cd threat-intelligence-extractor
