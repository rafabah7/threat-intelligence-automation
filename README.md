# Threat Intelligence Automation Platform

Automated system that monitors multiple cybersecurity intelligence sources, extracts vulnerability data, prioritizes critical findings, and delivers real-time alerts to defensive teams.

---

## Overview

Threat Intelligence Automation Platform streamlines the collection and processing of threat intelligence by automatically ingesting feeds such as the National Vulnerability Database and cybersecurity RSS sources.  
It classifies vulnerabilities based on CVSS scoring, prioritizes High and Critical issues, and notifies teams instantly through Telegram.  
Designed to reduce detection time and enhance operational efficiency for SOC Analysts, Threat Intelligence teams, and Blue Team operations.

---

## Architecture

(See: `docs/architecture.png`)

---

## Technologies

- Python  
- Flask  
- SQLite  
- Cron (scheduled tasks)  
- Telegram Bot API  

---

## Features

- Automated ingestion of NVD and cybersecurity RSS feeds  
- CVSS score extraction  
- Automatic High/Critical vulnerability prioritization  
- Real-time Telegram alerts  
- Web dashboard for visualization  
- Persistent storage using SQLite  

---

## Installation

Requires Python 3.9 or higher.
pip install -r requirements.txt

---

## Execution

python main.py

---

## Start the web dashboard

python dashboard/app.py

---

## Use Case

Built for:
- SOC Analysts
- Threat Intelligence Teams
- Blue Team Operations
The platform accelerates early detection of critical vulnerabilities and strengthens defensive response capabilities.
