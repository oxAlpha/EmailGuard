# Email IOC Extractor and Analyzer

**Email IOC Extractor and Analyzer** is a security tool designed to enhance email security by identifying and analyzing potential threats within email content. It parses and analyzes email headers, bodies, attachments, and URLs to detect common signs of phishing, malware, or other malicious activities. This tool is lightweight and available for both Windows and Linux platforms.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
  - [Windows](#windows)
  - [Linux](#linux)
- [Usage](#usage)
  - [Windows](#windows-1)
  - [Linux](#linux-1)
- [Command-Line Options](#command-line-options)
- [Capabilities](#capabilities)
  - [Email Analysis](#email-analysis)
  - [Threat Detection](#threat-detection)
  - [Logging and Reports](#logging-and-reports)
- [Dependencies](#dependencies)
  - [Windows](#windows-2)
  - [Linux](#linux-2)
- [Contributing](#contributing)
- [License](#license)

## Overview

The Email IOC Extractor and Analyzer helps cybersecurity professionals and system administrators identify malicious content in emails. Whether dealing with suspicious attachments, questionable links, or unusual email headers, the tool quickly scans and flags risky components. It supports both Windows and Linux, catering to a wide range of users.

## Features

- **Cross-Platform:** Available for both Windows (.exe) and Linux (.elf).
- **Email Parsing:** Extracts email components such as headers, body content, attachments, and URLs for analysis.
- **Phishing Detection:** Detects common phishing indicators, such as deceptive URLs or suspicious sender domains.
- **Malware Scanning:** Scans for potential malware in email attachments or embedded links.
- **Threat Intelligence:** Matches email data against known threat databases to identify malicious content.
- **Logging:** Saves detailed logs of all detected issues for further analysis.
- **Portable:** No installation required; just download and run.

## Installation

### Windows

1. Download the `EmailIOCExtractor.exe` file from the Releases section.
2. Place the file in a directory of your choice.
3. Run the executable directly.

### Linux

1. Download the `EmailIOCExtractor.elf` file from the Releases section.
2. Open your terminal and navigate to the directory where the file is located.
3. Make the file executable:

    ```bash
    chmod +x EmailGuard.elf
    ```

4. Run the executable:

    ```bash
    ./EmailGuard.elf
    ```

## Usage

### Windows

1. Open Command Prompt or PowerShell.
2. Run the tool using:

    ```bash
    EmailGuard.exe -email /path/to/your/email_file.eml -output /path/to/output_report.txt
    ```

### Linux

1. Open a terminal.
2. Run the tool using:

    ```bash
    ./EmailGuard.elf -email /path/to/your/email_file.eml -output /path/to/output_report.txt
    ```

## Command-Line Options

- `-email`: Path to the email file (in .eml format).
- `-output`: Path to the output report file. If not specified, results will be printed to the console.

## Capabilities

### Email Analysis

- Extracts IP addresses, email addresses, and URLs from email headers.
- Analyzes email attachments and computes their MD5, SHA1, and SHA256 hashes.

### Threat Detection

- Queries VirusTotal to check the status of IP addresses and file hashes.
- Detects potential phishing and malware threats based on analysis results.

### Logging and Reports

- Provides detailed logs of all detected issues.
- Outputs results to a report file or console.

## Dependencies

### Windows

- Python 3.x
- Required Python packages: `requests`

### Linux

- Python 3.x
- Required Python packages: `requests`

Install the necessary packages using pip:

```bash
pip install requests

