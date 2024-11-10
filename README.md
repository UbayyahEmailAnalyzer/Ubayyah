
	
<p align="center">
<img src="/images/Logo1.png"  width="500"/>
</p>

 # Ubayyah Email Analyzer
Ubayyah Email Analyzer is an email security tool designed to evaluate the authenticity and potential risks of an email. Using various checks, it assesses the email’s sender, content, attachments, and links to identify suspicious elements that may indicate phishing or other malicious intentions.
# Key Features and Functions: 




1. Authentication Checks:
   
	•	Verifies email integrity through SPF and DKIM records to determine if the email is sent from a verified source.

	•	Analyzes DMARC settings for additional insights into email authenticity.

3. Domain and URL Reputation:
   
	•	Examines the sender’s domain and URLs in the email body through the VirusTotal API to check if they are flagged by security vendors.

	•	Provides a summary of detected malicious URLs and flags any URLs that may pose a phishing risk.

5. Suspicious Content Detection:
   
	•	Identifies common phishing terms like “urgent,” “account,” and “password” within the email body.

	•	Looks for specific file extensions associated with malware (e.g., .exe, .bat) and flags them if present in attachments.

7. Attachment Analysis:
   
	•	Calculates hash values for attachments and uses VirusTotal to verify if they are recognized as malicious by security vendors.

	•	Reports suspicious file extensions and hashes, helping users assess attachment risks.

9. Risk Scoring:
    
	•	Categorizing emails as Clean, Suspicious, or Malicious based on predefined criteria (SPF/DKIM/DMARC results, domain reputation, detected URLs, attachment risks, etc.).

11. Comprehensive Report:
    
	•	Summarizes all findings, including sender details, detected suspicious content, URL checks, and attachment analyses, in a structured format.

# Screenshots


# Requirements:

• python3

• Virus Total API Key:

- Create a free account https://www.virustotal.com/gui/join-us
  
- Get your API Key https://youtu.be/9ftKViq71eQ

# Team Members
Abdullah Alfayez [linked-in](https://www.linkedin.com/in/abdullah-alfayez-768126243)

Khalid Alamri [linked-in](https://www.linkedin.com/in/khalid-alamri-457108202/)


