# Advanced LFI Scanner

[![Python Version](https://img.shields.io/badge/python-3.0%2B-blue)]()

---

## Overview

**Advanced LFI Scanner** — a simple and powerful scanner for detecting **Local File Inclusion (LFI)** vulnerabilities.  
Supports:

- Loading custom payloads from the `payloads_lfi.txt` file  
- Generating payload variants with URL encoding and filter bypass  
- Multithreading to speed up scanning  
- Web Application Firewall (WAF) detection  
- Beautiful progress bar and console output of results

---

## Features

- Easy to use with any payload file  
- Configurable thread count and timeouts  
- Automatic response analysis for LFI indicators  
- Checks headers and response body for WAF presence  
- Saves results to a file

---

## Requirements

- Python 3.0+  

---

## Installation


- git clone https://github.com/Afi0pchik/lfi-scanner.git 
- cd lfi-scanner
- chmod +x setup.sh
- ./setup.sh

---

## Usage

- python3 scanner.py "PASTE_YOUR_URL_HERE"

