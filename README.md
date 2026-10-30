# 🛡️ SmartPhish: Multi-Layer Phishing URL Detection System

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-black.svg)](https://flask.palletsprojects.com/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn-orange.svg)](https://scikit-learn.org/)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen.svg)](#)

**SmartPhish** is an intelligent, multi-layered phishing URL detection web application built with Flask and Scikit-Learn. Unlike simple blacklist checkers or single-model classifiers, SmartPhish combines a **Random Forest Machine Learning model** with **lexical rule heuristics**, **live DNS domain validation**, and **active SSL certificate inspection** to deliver accurate, multi-dimensional security verdicts in real time.

---

## 📌 Table of Contents
- [Features](#-features)
- [How It Works (Multi-Layer Architecture)](#-how-it-works-multi-layer-architecture)
- [Dataset & Model Training](#-dataset--model-training)
- [Project Structure](#-project-structure)
- [Installation & Setup](#-installation--setup)
- [Usage Guide](#-usage-guide)
- [Layer-Wise Scoring System](#-layer-wise-scoring-system)
- [Future Roadmap](#-future-roadmap)
- [License](#-license)

---

## 🚀 Features

- **Multi-Layer Hybrid Defense Engine**: Blends Machine Learning with network-level and heuristic validations.
- **Random Forest ML Classifier**: Trained on tens of thousands of legitimate and phishing URLs using the PhiUSIIL dataset.
- **Real-Time DNS Verification**: Identifies fake, non-existent, or unreachable domains using socket resolution.
- **Live SSL Certificate Inspection**: Validates SSL/TLS certificates and detects expired or missing encryption.
- **Lexical Pattern & Keyword Analysis**: Flags IP-based URLs, credential harvesting keywords (`login`, `verify`, `bank`), high-risk TLDs (`.tk`, `.ml`, `.ga`, etc.), and symbol spoofing.
- **Intuitive Web Interface**: Clean, responsive UI with color-coded alerts and an in-depth breakdown of layer-wise risk scores.

---

## 🔍 How It Works (Multi-Layer Architecture)

When a user submits a URL, SmartPhish passes it through four inspection layers before computing a final safety verdict:

```text
               User Input URL (e.g., http://secure-login-bank.tk/verify)
                                      │
                                      ▼
                             [ URL Normalization ]
                                      │
           ┌──────────────────────────┼──────────────────────────┐
           ▼                          ▼                          ▼
   [ 1. ML Layer ]            [ 2. Rule Layer ]          [ 3. Domain Layer ]
 - Lexical features         - Sensitive keywords       - Raw IP address check
 - Length & delimiters      - Symbol abuse (@, -)      - High-risk TLDs
 - Random Forest Predict    - Excessive URL length     - Active DNS resolution
           │                          │                          │
           └──────────────────────────┼──────────────────────────┘
                                      ▼
                              [ 4. SSL Layer ]
                        - Live TLS handshake (Port 443)
                        - Expiration & validity check
                                      │
                                      ▼
                        [ Decision & Scoring Engine ]
                   ┌──────────────────┼──────────────────┐
                   ▼                  ▼                  ▼
             Total Score ≥ 4     Invalid Domain      Safe & Valid
                   │                  │                  │
           ⚠️ Phishing Site   🚫 Invalid / Suspicious  ✅ Legitimate
The 4 Detection Layers:
Machine Learning Layer: Extracts 14 lexical and structural features (character counts, TLD indicators, protocol presence) and runs inference using a trained RandomForestClassifier.
Rule-Based Heuristic Layer: Flags suspicious indicators such as @ redirects, embedded credentials, excessive hyphens, and high-frequency phishing keywords (login, verify, secure, bank).
Domain Layer: Checks if the URL targets a raw IPv4 address, tests against known abusive free TLDs (.tk, .ml, .ga, .cf), and executes a live DNS lookup (socket.gethostbyname).
SSL/TLS Layer: Connects over port 443 to extract peer certificates and check validity dates. URL receives penalties if SSL is missing, unencrypted, or expired.
📊 Dataset & Model Training
The predictive model is trained using the PhiUSIIL Phishing URL Dataset, a comprehensive benchmark dataset consisting of hundreds of thousands of legitimate and malicious URLs.

Extracted Features (14 Dimensions):
URL total length
Counts of special characters: ., /, -, @, ?, %, =
Count of http occurrences
HTTPS indicator (Boolean 1 or 0)
Count of www occurrences
TLD token counts: .com, .net, .org
Model details:

Algorithm: RandomForestClassifier(n_estimators=100)
Artifact: Serialized to phishing_model.pkl via joblib
Training Notebook: 

MLMODEL.ipynb
