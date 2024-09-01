import re
import email
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage
import hashlib
import requests
import argparse
import time
import sys
from io import BytesIO
import whois

# Regular expressions for different IOCs
ip_regex = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
email_regex = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
url_regex = re.compile(r'https?://[^\s/$.?#].[^\s]*')

# VirusTotal API configuration
VIRUSTOTAL_API_KEY = '1d218fb8e20eee4dbec9e6ca568cb799aed60f0a1ac5f413b2406e39b0fa3dd7'
VIRUSTOTAL_URL_IP = 'https://www.virustotal.com/api/v3/ip_addresses/'
VIRUSTOTAL_URL_FILE = 'https://www.virustotal.com/api/v3/files/'

def print_banner():
    banner = """
    ============================================
        Email IOC Extractor and Analyzer
    ============================================
    """
    print(banner)

def dot_animation(message):
    for _ in range(3):
        sys.stdout.write(f"\r{message}{'.' * _}")
        sys.stdout.flush()
        time.sleep(0.5)
    print("\r" + message + " done!")

def extract_iocs_from_header(header_text):
    dot_animation("Extracting IOCs from headers")
    iocs = {
        'IP Addresses': list(set(ip_regex.findall(header_text))),
        'Emails': list(set(email_regex.findall(header_text))),
        'URLs': url_regex.findall(header_text),
    }
    return iocs

def get_authentication_results(header_text):
    dot_animation("Extracting authentication results")
    spf_result = None
    dkim_result = None
    dmarc_result = None

    for line in header_text.split('\n'):
        if line.startswith('Received-SPF:'):
            spf_result = line.split('Received-SPF:')[1].strip()
        elif line.startswith('Authentication-Results:'):
            results = line.split('Authentication-Results:')[1].strip()
            if 'dkim=' in results:
                dkim_result = re.search(r'dkim=([^\s;]+)', results).group(1)
            if 'spf=' in results:
                spf_result = re.search(r'spf=([^\s;]+)', results).group(1)
            if 'dmarc=' in results:
                dmarc_result = re.search(r'dmarc=([^\s;]+)', results).group(1)

    return {
        'SPF': spf_result,
        'DKIM': dkim_result,
        'DMARC': dmarc_result,
    }

def get_attachment_hashes(part):
    dot_animation(f"Calculating hashes for {part.get_filename()}")
    hashes = {
        'MD5': hashlib.md5(),
        'SHA1': hashlib.sha1(),
        'SHA256': hashlib.sha256(),
    }
    attachment_data = BytesIO(part.get_payload(decode=True))
    for chunk in iter(lambda: attachment_data.read(4096), b""):
        for algo in hashes.values():
            algo.update(chunk)
    attachment_data.seek(0)  # Reset file pointer to the beginning
    return {name: algo.hexdigest() for name, algo in hashes.items()}

def parse_email(file_path):
    dot_animation("Parsing email")
    with open(file_path, 'rb') as file:
        msg = BytesParser(policy=policy.default).parse(file)
    
    header_text = ""
    extracted_headers = {
        'Reply-To': msg.get('Reply-To'),
        'Return-Path': msg.get('Return-Path'),
        'X-Sender-IP': msg.get('X-Sender-IP'),
        'Message-ID': msg.get('Message-ID'),
        'Sender Email': msg.get('From'),
        'Receiver Email': msg.get('To'),
    }
    
    for header, value in msg.items():
        header_text += f"{header}: {value}\n"

    attachments = []
    if isinstance(msg, EmailMessage):
        for part in msg.iter_parts():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is not None:
                filename = part.get_filename()
                if filename:
                    attachment_data = {
                        'filename': filename,
                        'hashes': get_attachment_hashes(part),
                    }
                    attachments.append(attachment_data)
    
    return header_text, extracted_headers, attachments

def check_ip_virustotal(ip):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    dot_animation(f"Checking IP {ip} on VirusTotal")
    response = requests.get(f"{VIRUSTOTAL_URL_IP}{ip}", headers=headers)
    if response.status_code == 200:
        data = response.json()
        last_analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        if last_analysis_stats.get('malicious', 0) > 0:
            return 'malicious', f'For more details, visit VirusTotal: https://www.virustotal.com/gui/ip-address/{ip}'
        else:
            return 'benign', f'For more details, visit VirusTotal: https://www.virustotal.com/gui/ip-address/{ip}'
    else:
        return 'unknown', response.text

def check_md5_virustotal(md5):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY
    }
    dot_animation(f"Checking MD5 {md5} on VirusTotal")
    response = requests.get(f"{VIRUSTOTAL_URL_FILE}{md5}", headers=headers)
    if response.status_code == 200:
        data = response.json()
        last_analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
        if last_analysis_stats.get('malicious', 0) > 0:
            return 'malicious', f'For more details, visit VirusTotal: https://www.virustotal.com/gui/file/{md5}'
        else:
            return 'benign', f'For more details, visit VirusTotal: https://www.virustotal.com/gui/file/{md5}'
    else:
        return 'unknown', response.text

def whois_lookup(ip):
    try:
        dot_animation(f"Performing Whois lookup for IP {ip}")
        w = whois.whois(ip)
        whois_info = {
            'Domain': w.get('domain_name', ''),
            'Registrar': w.get('registrar', ''),
            'Creation Date': w.get('creation_date', ''),
            'Expiration Date': w.get('expiration_date', ''),
            'Updated Date': w.get('updated_date', ''),
            'Name Servers': ', '.join(filter(None, w.get('name_servers', [])))  # Ensure we only join valid strings
        }
        return whois_info
    except Exception as e:
        return {'Error': str(e)}

def print_section(title, content):
    print("\n" + "="*50)
    print(f"{title}")
    print("="*50)
    print(content)
    print("\n" + "="*50)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='Extract IOCs, attachments, and authentication results from email headers.')
    parser.add_argument('-email', type=str, required=True, help='Path to the email file (in .eml format)')
    args = parser.parse_args()
    
    header_text, extracted_headers, attachments = parse_email(args.email)
    iocs = extract_iocs_from_header(header_text)
    auth_results = get_authentication_results(header_text)
    
    ioc_content = "Extracted_IPs:\n"
    for ip in iocs.get('IP Addresses', []):
        ioc_content += f"  {ip}\n"
        whois_info = whois_lookup(ip)
        if 'Error' in whois_info:
            ioc_content += f"    Whois Info Error: {whois_info['Error']}\n"
        else:
            for key, value in whois_info.items():
                ioc_content += f"    {key}: {value}\n"
    
    email_content = "Extracted_Emails:\n"
    for email in iocs.get('Emails', []):
        email_content += f"  {email}\n"
    
    url_content = "Extracted_URLs:\n"
    for url in iocs.get('URLs', []):
        url_content += f"  {url}\n"
    
    attachment_content = "Attachments and their Hashes:\n"
    for attachment in attachments:
        attachment_content += f"Filename: {attachment['filename']}\n"
        for hash_type, hash_value in attachment['hashes'].items():
            attachment_content += f"  {hash_type}: {hash_value}\n"
        md5_status, md5_message = check_md5_virustotal(attachment['hashes']['MD5'])
        attachment_content += f"  VirusTotal MD5 Result: {md5_status} ({md5_message})\n"
    
    auth_content = "Authentication Results:\n"
    for key, value in auth_results.items():
        auth_content += f"{key}: {value}\n"
    
    header_content = "Extracted Headers:\n"
    for header, value in extracted_headers.items():
        if header == 'X-Sender-IP':
            header_content += f"Sender-IP: {value}\n"
        elif header == 'Sender Email':
            header_content += f"Sender-Email: {value}\n"
        elif header == 'Receiver Email':
            header_content += f"Receiver-Email: {value}\n"
        else:
            header_content += f"{header}: {value}\n"
    
    print_section("IOCs extracted from headers", ioc_content + email_content + url_content)
    print_section("Attachments and their Hashes", attachment_content)
    print_section("Authentication Results", auth_content)
    print_section("Extracted Headers", header_content)

    print_section("VirusTotal IP Results", '\n'.join(f"IP: {ip}\n  Result: {check_ip_virustotal(ip)[0]} ({check_ip_virustotal(ip)[1]})" for ip in iocs.get('IP Addresses', [])))

if __name__ == "__main__":
    main()
