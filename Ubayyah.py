print(     
"""          
                        #    #
                                            %%% ##   ##
                                         %%%%% ###%%###
                                        %%%%% ### %%% #
                                      %%%%%% ### %%% ###
                                       %%%% ## %% #####
                                      %%%%% # % #######
                                    %%%%%% # % ########
                                   %%%%% ##### #########
                         ###        %% ####### #########
                %%% ############    ########### ########
             %%%% ############################### #######
           %%%%% ################################## ######
         %%%%%% #################################### #####
        %%%%%% #####################################  ###
        %%%%% #######################################
       %%%%%% ########################################
    % %%%%%%% ########################################
     %%%%%%%%% #######################################
    %%%%%%%%%% ########################################
 %%% %%%%%%%%   ###### ################################
   %%%%%%%%      ###### #################### ##########
% %%%%%%%%        ####### ########### ###### ##########
 %%%%%%%%%         #######  ########### ###### ########
%%%%%%%%%%          ##### ###  ######### ####### ######
 %%%%%%%%%%          #### ##               ####### ####
 %%%%%%%%%%%           ## #                  ##### ###
  %%  %% % %%         # ##                      ## ###
    %   %    %        # ###                      # ###
                       # ###                     ## ###
                       # ###                     ## ###
                       # ####                   #### ##
                      ### ###                  ##### ###
                     ####  ###                 ####   ##
                    #####   ###                 ##    ##
                   #####    ####                      ###
                    ##        ###                     ###
                               ####                     ##
                                ####                    ###
                                                        ####
                                                         ##
""")



import email
import re
import requests
import hashlib
from tabulate import tabulate
from urllib.parse import urlparse

# Replace with your VirusTotal API key
VT_API_KEY = 'your_api_key_here'

# VirusTotal API URLs
URL_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
FILE_REPORT_URL = 'https://www.virustotal.com/api/v3/files/'

# List of suspicious words/phrases typically used by attackers
SUSPICIOUS_WORDS = {
    "urgent": "Attackers often create a sense of urgency to trick the victim into taking quick action.",
    "bank": "Phishing attacks commonly reference banks to steal financial information.",
    "password": "Attackers might ask for passwords directly or try to steal them via phishing.",
    "login": "Phishing emails often ask victims to log in to fake sites to steal credentials.",
    "click": "Attackers frequently ask victims to click on links that lead to malicious websites.",
    "verify": "Emails asking to 'verify' account details might be attempts to steal sensitive information.",
    "attachment": "Attachments may contain malware or viruses.",
    "reset": "Phishing attacks may offer fake password reset links to steal credentials.",
    "account": "Emails related to account issues can be attempts to phish personal information.",
    "security": "Attackers often use security concerns as a pretext for phishing.",
    "confidential": "Emails mentioning confidential information might be trying to lure victims into revealing sensitive data.",
    "offer": "Scams and phishing attacks often involve fake offers or promotions.",
    "update": "Fake update requests may be used to steal personal or financial information.",
    "Free" : "Attackers use the word free to entice victims with the promise of no cost, which can lower defenses and encourage clicks.",
    "download": "The attacker may use the word download to prompt users to install files that could be malicious",
    "Congratulations": "The attacker may use the word congratulations to imply that the victim has won something, encouraging engagement and interaction.",
    "Congrats": "The attacker may use the word congrats to imply that the victim has won something, encouraging engagement and interaction."
}

# Risky file extensions with descriptions
RISKY_EXTENSIONS = {
    '.exe': "Suspicious file extension could be used to distribute malware or ransomware.",
    '.bat': "Suspicious file extension could be used to execute commands on Windows. Can be used to run malicious scripts.",
    '.msi': "Suspicious file extension could be used to install software, including malicious programs.",
    '.vbs': "Visual Basic Script files. Can contain and execute malicious scripts.",
    '.js': "JavaScript files. Can be used to execute harmful code when run in a browser or in some email clients.",
    '.wsf': "Windows Script File. Can execute scripts written in multiple scripting languages.",
    '.zip': "Compressed archive files. Often used to bundle malicious files or executables.",
    '.rar': "Suspicious file extension could contain multiple malicious files.",
    '.iso': "Disc image files. Can contain large amounts of data, including executables or malware.",
    '.scr': "Screensaver files on Windows. These can be renamed executable files and could be used to deliver malware.",
    '.pif': "Program Information File. Can be used to run executable code on older versions of Windows."
}

# List of common personal email providers
PERSONAL_EMAIL_PROVIDERS = {
    'yahoo.com',
    'gmail.com',
    'hotmail.com',
    'aol.com',
    'outlook.com',
    'icloud.com',
    'mail.com',
    'zoho.com',
    'protonmail.com'
}

# Function to decode text
def decode_text(text):
    if text is None:
        return ""
    if isinstance(text, bytes):
        try:
            decoded = text.decode('utf-8')
        except UnicodeDecodeError:
            decoded = text.decode('latin-1')
    else:
        decoded = text
    return decoded

# Function to extract email information
def extract_email_info(email_file):
    try:
        with open(email_file, 'r') as f:
            msg = email.message_from_file(f)

        spf_match = re.search(r'spf=([a-zA-Z]+)', msg.get('Authentication-Results', ''))
        spf = spf_match.group(1) if spf_match else 'SPF record not found'

        dkim_match = re.search(r'dkim=([a-zA-Z]+)', msg.get('Authentication-Results', ''))
        dkim = dkim_match.group(1) if dkim_match else 'DKIM signature not found'

        dmarc_match = re.search(r'dmarc=([a-zA-Z]+)', msg.get('Authentication-Results', ''))
        dmarc = dmarc_match.group(1) if dmarc_match else 'DMARC record not found'

        sender_email = re.search(r'[\w\.-]+@[\w\.-]+', msg.get('From', '')).group(0)
        sender_domain = sender_email.split('@')[-1]

        subject = msg.get('Subject', 'No Subject')

        email_body = ""
        attachment_names = []
        attachment_hashes = []
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == 'text/plain':
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset()
                if charset:
                    email_body += decode_text(payload.decode(charset))
                else:
                    email_body += decode_text(payload)
            elif content_type != 'text/plain' and part.get_filename():
                attachment_names.append(part.get_filename())
                file_content = part.get_payload(decode=True)
                file_hash = hashlib.sha256(file_content).hexdigest()
                attachment_hashes.append((part.get_filename(), file_hash))

        if not attachment_names:
            attachment_names.append('No Attachment')

        return spf, dkim, dmarc, sender_email, sender_domain, subject, attachment_names, email_body, attachment_hashes
    except Exception as e:
        print(f"Error extracting email info: {e}")
        return None, None, None, None, None, None, None, None, None

# Function to detect suspicious words
def detect_suspicious_words(email_body):
    email_body_lower = email_body.lower()
    found_words = {}

    for word, reason in SUSPICIOUS_WORDS.items():
        if word in email_body_lower:
            found_words[word] = reason

    return found_words

# Function to extract URLs from the email body
def extract_urls(email_body):
    url_pattern = r'(https?://[^\s]+|www\.[^\s]+)'
    urls = re.findall(url_pattern, email_body)
    return urls

# Function to check domain reputation
def check_domain_reputation(domain):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {
        'x-apikey': VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        try:
            reputation = data['data']['attributes']['last_analysis_stats']['malicious']
            return reputation
        except KeyError:
            return "No reputation data available for this domain."
    else:
        return f"Error fetching data: {response.status_code} - {response.text}"

# Function to check file hash reputation
def check_file_reputation(file_hash):
    url = f"{FILE_REPORT_URL}{file_hash}"
    headers = {
        'x-apikey': VT_API_KEY
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        try:
            # Check if the file hash is known
            if 'data' in data:
                last_analysis_stats = data['data']['attributes']['last_analysis_stats']
                total_detected = last_analysis_stats.get('malicious', 0)
                total_scan = sum(last_analysis_stats.values())
                
                if total_detected > 0:
                    return f"The hash has {total_detected} hits in VT"
                else:
                    return f"The hash has {total_detected} hits in VT"
            else:
                return "Unknown file hash in VT"
        except KeyError:
            return "Error parsing file reputation data"
    else:
         return "Unknown file hash in VT"

# Function to clean and check URLs with VirusTotal
def check_url_virustotal(url):
    cleaned_url = url.rstrip('>')  # Remove trailing '>'
    params = {'apikey': VT_API_KEY, 'resource': cleaned_url}
    response = requests.get(URL_REPORT_URL, params=params)
    
    if response.status_code == 200:
        result = response.json()
        if result.get('response_code') == 1:
            total_detected = sum(1 for scan in result.get('scans', {}).values() if scan.get('detected'))
            phishing_detected = sum(1 for scan in result.get('scans', {}).values() if scan.get('result') and 'phish' in scan.get('result').lower())
            total_scans = len(result.get('scans', {}))
            return total_detected, phishing_detected, total_scans, None  # No error
        else:
            return None, None, None, 'Error'
    else:
        domain = urlparse(cleaned_url).netloc
        domain_hits = check_domain_reputation(domain)
        return None, None, None, f"Error occurred with the full URL, but the domain has {domain_hits} hits."

# Function to shorten URL for readability
def shorten_url(url):
    return url if len(url) <= 60 else f"{url[:40]}...{url[-30:]}"

# Function to analyze email body
def analyze_email(email_body):
    suspicious_words = detect_suspicious_words(email_body)
    urls = extract_urls(email_body)

    # Collecting URL details
    url_details = []
    if urls:
        for url in urls:
            cleaned_url = url.rstrip('>')
            total_detected, phishing_detected, total_scans, error = check_url_virustotal(cleaned_url)
            if error:
                url_details.append(f" {shorten_url(url)} Timeout error accursed")
            else:
             url_details.append(f"  URL: {shorten_url(url)} Number of security vendors flagged it as malicious ({total_detected} out of {total_scans} scans detected it, {phishing_detected} consider it phishing).")
    
    # Combining suspicious words and URL details
    analysis_results = []
    if suspicious_words:
        for word, reason in suspicious_words.items():
            analysis_results.append(f"- {word}: {reason}")
    else:
        analysis_results.append("No suspicious words detected.")
    
    analysis_results.extend(url_details)
    
    return "\n".join(analysis_results) if analysis_results else "No suspicious words or URLs detected."

# Function to check risky file extensions
def check_risky_file_extensions(attachment_names):
    risky_files = []
    for name in attachment_names:
        for ext, message in RISKY_EXTENSIONS.items():
            if name.lower().endswith(ext):
                risky_files.append((name, message))
                break
    return risky_files

# Function to analyze email maliciousness
def analyze_email_maliciousness(email_body):
    if "urgent" in email_body.lower() or "account" in email_body.lower():
        return "High", "The email contains high-risk keywords suggesting potential maliciousness."
    return "Low", "No high-risk keywords detected."

# Main program
# Main program
if __name__ == "__main__":
    try:
        email_file = input("Enter the path to the email file: ")
        spf, dkim, dmarc, sender_email, sender_domain, subject, attachment_names, email_body, attachment_hashes = extract_email_info(email_file)

        if spf is None or dkim is None:
            print("Error extracting SPF or DKIM information. Please check the email file format.")
        else:
            # Analyze email body for suspicious words and URLs
            suspicious_words = detect_suspicious_words(email_body)
            email_body_analysis = analyze_email(email_body)

            # Determine Ubayyah Analysis Summary
            if spf == "pass" and dkim == "pass":
                ubayyah_analysis_summary = "- (spf pass, dkim pass) The email is verified and unmodified"
            elif spf == "fail" and dkim == "fail":
                ubayyah_analysis_summary = "- (spf failed, dkim failed) The email is unauthorized/unverified and potentially tampered"
            elif spf == "pass" and dkim == "fail":
                ubayyah_analysis_summary = "- (spf pass, dkim failed) The email is from an authorized sender, but its integrity might have been tampered."
            elif spf == "fail" and dkim == "pass":
                ubayyah_analysis_summary = "- (spf failed, dkim pass) The email is unauthorized/unverified, but the email's content appears authentic."
            else:
                ubayyah_analysis_summary = "- SPF or DKIM was not found."

            # Check if email is from a personal email provider
            if sender_domain in PERSONAL_EMAIL_PROVIDERS:
                ubayyah_analysis_summary += "\n\n- Received from a personal email provider."

            # Check domain reputation and include in the Ubayyah Analysis Summary
            reputation1 = f"{check_domain_reputation(sender_domain)} security vendors flagged it as malicious"
            ubayyah_analysis_summary += f"\n\n- Reputation of sender's domain: {reputation1}"

            # Check for risky file extensions
            risky_files = check_risky_file_extensions([name for name, _ in attachment_hashes])
            if risky_files:
                ubayyah_analysis_summary += "\n\n- Received files with risky extensions detected:"
                for file, message in risky_files:
                    ubayyah_analysis_summary += f"\n  Risky file: {file} - {message}"
            else:
                ubayyah_analysis_summary += "\n\n- No Suspicious File Extension Observed."

            # Analyze each attachment hash
            formatted_attachments_info = []  # List to store formatted file info
            file_hash_hits_info = []  # List to store file hash hits info

            for file_name, file_hash in attachment_hashes:
                reputation = check_file_reputation(file_hash)
                formatted_info = f"{file_name}, {file_hash}, {reputation}"
                formatted_attachments_info.append(formatted_info)

                # Add file hash hits to Ubayyah Analysis Summary
                file_hash_hits_info.append(f"  {file_name} ({file_hash}) - {reputation}")

            # Add file hash hits to Ubayyah Analysis Summary
            if file_hash_hits_info:
                ubayyah_analysis_summary += "\n\n- File hash hits detected:"
                for hit in file_hash_hits_info:
                    ubayyah_analysis_summary += f"\n  {hit}"
            else:
                ubayyah_analysis_summary += "\n\n- No file hash hits detected."

            # Add suspicious words to Ubayyah Analysis Summary
            if suspicious_words:
                ubayyah_analysis_summary += "\n\n- Suspicious words detected:"
                for word, reason in suspicious_words.items():
                    ubayyah_analysis_summary += f"\n  {word}: {reason}"
            else:
                ubayyah_analysis_summary += "\n\n- No suspicious words detected."

            # Analyze URLs
            urls = extract_urls(email_body)
            any_url_with_hits = False  # Flag to check if any URL has hits
            if urls:
                for url in urls:
                    cleaned_url = url.rstrip('>')
                    total_detected, phishing_detected, total_scans, error = check_url_virustotal(cleaned_url)
                    if error:
                        # Skip error message
                        continue
                    if total_detected >= 1:
                        any_url_with_hits = True  # Set the flag if any URL has hits
                        # Append detailed information about the URL
                        ubayyah_analysis_summary += f"\n\n- URL with hits: {shorten_url(url)} flagged as malicious ({total_detected} out of {total_scans} scans detected it, {phishing_detected} consider it phishing)."

            # Add note for URLs with no hits
            if not any_url_with_hits and urls:
                ubayyah_analysis_summary += "\n\n- No hits were found for the URLs. Manual investigation is recommended."

            # **Start of the Scoring Logic**
            score = 0

            # SPF scoring
            if spf == "fail":
                score += 30

            # DKIM scoring
            if dkim == "fail":
                score += 5

            # DMARC scoring
            if dmarc == "fail":
                score += 5

            # Sender Domain Reputation scoring
            domain_reputation = check_domain_reputation(sender_domain)
            if domain_reputation is None:
                score += 0  # No impact
            elif domain_reputation == 0:
                score += 0  # No impact
            else:
                score += 10  # Deduct points for reputation > 0

            # URL Reputation scoring
            for url in extract_urls(email_body):
                total_detected, _, _, _ = check_url_virustotal(url)
                if total_detected is None:
                    score += 0
                elif total_detected > 0:
                    score += 30
                else:
                    score += 0

            # File Hash scoring
            
            for _, file_hash in attachment_hashes:
                file_reputation = check_file_reputation(file_hash)
                if file_reputation == "The hash has 0 hits in VT":
                    score -= 0  # No impact
                elif file_reputation is None:
                    score -= 0  # No impact
                elif file_reputation == "Unknown file hash in VT":
                     score -= 0
                else:
                    score += 15

            # Suspicious File Extensions scoring
            if risky_files:
                score += 5
            else:
                score -= 0  # No impact


            # Score categories
            if 10 > score >= 0:
                score_message = "Clean"
            elif 29 >= score >= 10:
                score_message = "Suspicious"
            else: 
               score_message = "Malicious"


            # Final email analysis
            table_data = [
                ['Field', 'Value'],
                ['Subject', subject],
                ['SPF', spf],
                ['DKIM', dkim],
                ['DMARC', dmarc],
                ['Sender Email', sender_email],
                ['Reputation of sender\'s domain', reputation1],
                ['Sender Domain', sender_domain],
                ['FileName/Hash/VT Hits:', '\n'.join(formatted_attachments_info)],  # Updated field name and value
                ['Email Body Analysis', email_body_analysis],  # Analysis including URLs
                ['Ubayyah Analysis Summary', ubayyah_analysis_summary],
                ['ThreatLevel', f"{score_message}"]  # Added the final score here
            ]

            print(tabulate(table_data, tablefmt='grid'))
    except Exception as e:
        print(f"An error occurred: {e}")

