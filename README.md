
# Threat Intelligence Extractor 🛡️

A **Python-based tool** to extract threat intelligence from cybersecurity reports using **Natural Language Processing (NLP)** and the **VirusTotal API**. This tool automatically extracts key threat intelligence data, including Indicators of Compromise (IoCs), Tactics, Techniques, and Procedures (TTPs), Threat Actors, Malware details, and Targeted Entities.

---

## Features ✨

- **Regex-based IoC Extraction**: Extracts IP addresses, domains, email addresses, and file hashes.
- **spaCy Named Entity Recognition (NER)**: Detects threat actors and targeted entities.
- **MITRE ATT&CK Mapping**: Maps tactics and techniques to the MITRE ATT&CK framework.
- **VirusTotal API Integration**: Enriches malware details with hashes, tags, and more.
- **Structured Output**: Returns results in a clean, JSON-like dictionary format.
- **Streamlit Web UI**: User-friendly interface for uploading PDFs or pasting report text.
- **Visualizations**: Interactive bar charts for IoCs and summaries of extracted data.
- **Downloadable Results**: Export extracted threat intelligence as a JSON file.

---

## Requirements 📋

- **Python 3.8+**
- **Libraries**:
  - `spacy` (for Named Entity Recognition)
  - `requests` (for API calls to VirusTotal)
  - `pdfplumber` (for extracting text from PDFs)
  - `streamlit` (for the web UI)
  - `pandas` (for data manipulation)
  - `plotly.express` (for visualizations)
- **VirusTotal API Key**: [Get your free API key here](https://www.virustotal.com/).

---

## Installation 🛠️

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/higgn/threat-intelligence-extractor.git
   cd threat-intelligence-extractor
   ```

2. **Install Required Libraries**:
   ```bash
   pip install spacy requests pdfplumber streamlit pandas plotly
   ```

3. **Download spaCy Model**:
   ```bash
   python -m spacy download en_core_web_sm
   ```

4. **Add VirusTotal API Key**:
   Replace the placeholder in the script with your actual VirusTotal API key:
   ```python
   VIRUSTOTAL_API_KEY = "your_virustotal_api_key_here"
   ```

---

## Usage 🚀

1. **Run the Script**:
   ```bash
   streamlit run threat_intelligence_extractor.py
   ```

2. **Upload a PDF or Paste Report Text**:
   - Use the file uploader to upload a PDF file.
   - Alternatively, paste the report text into the text area.

3. **View Extracted Threat Intelligence**:
   - The tool will display:
     - Indicators of Compromise (IoCs)
     - Tactics, Techniques, and Procedures (TTPs)
     - Threat Actors
     - Malware Details
     - Targeted Entities
   - Interactive visualizations and summaries are also provided.

4. **Download Results**:
   - Click the "Download Threat Intelligence as JSON" button to save the results.

---

## Example Output 📄

### Input:
```plaintext
The APT33 group, suspected to be from Iran, has launched a new campaign targeting the energy sector organizations. The attack utilizes Shamoon malware, known for its destructive capabilities. The threat actor exploited a vulnerability in the network perimeter to gain initial access. The malware was delivered via spear-phishing emails containing a malicious attachment. The malware's behavior was observed communicating with IP address 192.168.1.1 and domain example.com. The attack also involved lateral movement using PowerShell scripts.
```

### Output:
```json
{
  "IoCs": {
    "IP addresses": ["192.168.1.1"],
    "Domains": ["example.com"],
    "Email addresses": [],
    "File hashes": []
  },
  "TTPs": {
    "Tactics": [
      {"TA0001": "Initial Access"},
      {"TA0002": "Execution"},
      {"TA0008": "Lateral Movement"}
    ],
    "Techniques": [
      {"T1566.001": "Spear Phishing Attachment"},
      {"T1059.001": "PowerShell"}
    ]
  },
  "Threat Actor(s)": ["APT33"],
  "Malware": [
    {"Name": "Shamoon"}
  ],
  "Targeted Entities": ["Energy Sector"]
}
```

---

## Screenshots 📸

### 1. **Streamlit Web UI**
![image](https://github.com/user-attachments/assets/2f9b44b5-5bd1-4ba6-a4ef-a6301d2993ae)

### 2. **Extracted Threat Intelligence**
![image](https://github.com/user-attachments/assets/5ac03ad3-2c65-4e8a-8c20-3f323d777e7e)

### 3. **IoCs Visualization**
![image](https://github.com/user-attachments/assets/06698d2d-328a-4ef6-9197-6ee285053dba)

### 4. **Downloadable Results**
![image](https://github.com/user-attachments/assets/41d0b157-6082-4c16-913e-f519e10f9b84)

---

## Documentation 📚

### **Extraction Logic**
1. **Indicators of Compromise (IoCs)**:
   - IP addresses, domains, email addresses, and file hashes are extracted using regex patterns.
   - System file extensions are filtered out to reduce false positives.

2. **Tactics, Techniques, and Procedures (TTPs)**:
   - Tactics and techniques are mapped to the MITRE ATT&CK framework using predefined mappings.

3. **Threat Actors**:
   - Detected using spaCy's Named Entity Recognition (NER) with the `ORG` label.

4. **Malware**:
   - Malware names are extracted using spaCy's NER with the `PRODUCT` label.
   - File hashes are enriched using the VirusTotal API.

5. **Targeted Entities**:
   - Detected using spaCy's NER with the `ORG` and `GPE` labels.

---

## Limitations and Future Improvements 🚧

### **Limitations**:
- **Accuracy of NER**: spaCy's NER may produce false positives or miss some entities.
- **VirusTotal API Rate Limits**: The free tier of the VirusTotal API has rate limits.
- **PDF Parsing**: Complex PDFs with images or non-standard formatting may not be parsed correctly.

### **Future Improvements**:
- **Advanced NER Models**: Use custom-trained NER models for better accuracy.
- **Multi-Language Support**: Extend support for non-English reports.
- **Customizable Outputs**: Allow users to specify which fields to extract.
- **Integration with Other APIs**: Add support for additional threat intelligence sources.

---

## Contributing 🤝

Contributions are welcome! If you'd like to contribute, please follow these steps:
1. Fork the repository.
2. Create a new branch for your feature or bugfix.
3. Submit a pull request with a detailed description of your changes.

---

## License 📜

Will add soon ..........
---

## Acknowledgments 🙏

- **spaCy**: For providing an excellent NLP library.
- **VirusTotal**: For their comprehensive malware analysis API.
- **MITRE ATT&CK**: For their invaluable framework for understanding adversary behavior.
- **Streamlit**: For making it easy to build interactive web apps.

---

## Contact 📧

For questions or feedback, please reach out to:

- **GitHub**: [higgn](https://github.com/higgn)

---

```

THIS IS SUBMITTED TO HACK IITK CHALLENGE ROUND 1 / DO NOT STEAL THIS CODE 
