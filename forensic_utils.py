import os
import magic
from PIL import Image, ExifTags
from PyPDF2 import PdfReader
# PasswordType import is REMOVED for PyPDF2 < 3.0.0 compatibility
from PyPDF2.errors import DependencyError as PyPDF2LibDependencyError 
import olefile
from datetime import datetime
import math
import collections
import numpy as np
import re 

from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT, TA_CENTER
from io import BytesIO
from flask import current_app

def calculate_shannon_entropy(data_bytes):
    if not data_bytes: return 0.0
    byte_counts = collections.Counter(data_bytes); data_len = len(data_bytes); entropy = 0.0
    for count in byte_counts.values(): probability = count / data_len; entropy -= probability * math.log2(probability)
    return entropy

def detect_lsb_steganography_pil(image_path, threshold=0.05):
    try:
        img = Image.open(image_path).convert('RGB'); pixels = np.array(img)
        lsb_r, lsb_g, lsb_b = (pixels[:,:,0] % 2).flatten(), (pixels[:,:,1] % 2).flatten(), (pixels[:,:,2] % 2).flatten()
        entropy_r, entropy_g, entropy_b = calculate_shannon_entropy(lsb_r), calculate_shannon_entropy(lsb_g), calculate_shannon_entropy(lsb_b)
        avg_entropy_lsb = (entropy_r + entropy_g + entropy_b) / 3.0
        if 0.90 < avg_entropy_lsb <= 1.0: return "LSB plane: High entropy (potential encrypted/random data in LSBs)."
        elif avg_entropy_lsb < 0.7: return "LSB plane: Lower entropy (potential simple steganography hint)."
        else: return "LSB plane: Entropy appears typical."
    except Exception as e: return f"LSB check error: {str(e)}"

def get_file_metadata(file_path):
    metadata = {}
    if not os.path.exists(file_path): metadata['error'] = f"File not found: {file_path}"; return metadata
    try:
        metadata['file_type_mime'] = magic.from_file(file_path, mime=True)
        metadata['file_name'] = os.path.basename(file_path)
        file_size = os.path.getsize(file_path); metadata['file_size_bytes'] = file_size
        metadata['last_modified'] = datetime.fromtimestamp(os.path.getmtime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
        metadata['created_time'] = datetime.fromtimestamp(os.path.getctime(file_path)).strftime('%Y-%m-%d %H:%M:%S')
        file_bytes = b""; 
        try:
            with open(file_path, 'rb') as f: file_bytes = f.read()
        except Exception as e: metadata['file_read_error'] = str(e)
        if file_bytes:
            entropy = calculate_shannon_entropy(file_bytes); metadata['shannon_entropy'] = f"{entropy:.4f}"
            if entropy > 7.5 and file_size > 1024: metadata['entropy_analysis'] = "High (potential encryption/compression)"
            elif entropy < 2.0 and file_size > 100: metadata['entropy_analysis'] = "Low (sparse or simple text/data)"
            else: metadata['entropy_analysis'] = "Moderate"
            if file_bytes.startswith(b'%PDF-'): metadata['signature_match'] = "PDF" 
            elif file_bytes.startswith(b'\x89PNG\r\n\x1a\n'): metadata['signature_match'] = "PNG Image"
            elif file_bytes.startswith(b'\xff\xd8\xff'): metadata['signature_match'] = "JPEG Image"
            elif file_bytes.startswith(b'GIF87a') or file_bytes.startswith(b'GIF89a'): metadata['signature_match'] = "GIF Image"
            elif file_bytes.startswith(b'PK\x03\x04'):
                metadata['signature_match'] = "ZIP Archive (Office Open XML, etc.)"
                if metadata['file_type_mime'] in ['application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                                    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                                    'application/vnd.openxmlformats-officedocument.presentationml.presentation']:
                    metadata['signature_match'] += " - Confirmed Office Open XML"

        if metadata['file_type_mime'].startswith('image/'):
            metadata.update(get_image_exif_data(file_path))
            if file_bytes: lsb_hint = detect_lsb_steganography_pil(file_path);_ = lsb_hint and metadata.setdefault('steganography_lsb_hint', lsb_hint)
        elif metadata['file_type_mime'] == 'application/pdf': metadata.update(get_pdf_metadata(file_path)) 
        elif olefile.isOleFile(file_path): metadata.update(get_ole_metadata(file_path))
    except Exception as e: metadata['extraction_error'] = str(e)
    return metadata

def get_image_exif_data(image_path):
    exif_data = {}
    try:
        image = Image.open(image_path)
        try: TAGS_DICT = ExifTags.TAGS
        except AttributeError: TAGS_DICT = {v: k for k, v in Image.TAGS.items()} if hasattr(Image, 'TAGS') else {}
        exif = image.getexif()
        if exif:
            for tag_id, value in exif.items():
                tag_name = TAGS_DICT.get(tag_id, tag_id)
                exif_data[str(tag_name)] = str(value.decode('utf-8', 'replace') if isinstance(value, bytes) else value)
        exif_data['dimensions'] = f"{image.width}x{image.height}"; exif_data['format'] = image.format; exif_data['mode'] = image.mode
    except Exception as e: exif_data['exif_error'] = f"EXIF read error: {str(e)}"
    return exif_data

def get_pdf_metadata(pdf_path): # VERSION FOR PyPDF2 < 3.0.0
    pdf_meta = {}; text_content = ""
    try:
        reader = PdfReader(pdf_path)
        meta = reader.metadata
        if meta:
            attrs = ['author', 'creator', 'producer', 'subject', 'title'] 
            for attr in attrs: 
                if val := getattr(meta, attr, None): pdf_meta[f'pdf_{attr}'] = str(val)
            if hasattr(meta, 'creation_date') and meta.creation_date:
                pdf_meta['pdf_creation_date'] = str(meta.creation_date)
            if hasattr(meta, 'modification_date') and meta.modification_date:
                pdf_meta['pdf_modification_date'] = str(meta.modification_date)

        pdf_meta['num_pages'] = len(reader.pages)
        pdf_meta['is_encrypted'] = "Yes" if reader.is_encrypted else "No"
        if reader.is_encrypted:
            try:
                decryption_status_code = reader.decrypt('') 
                
                if decryption_status_code == 0:
                    pdf_meta['encryption_status'] = "Encrypted (but accessible with empty/no password)"
                elif decryption_status_code == 1:
                    pdf_meta['encryption_status'] = "Encrypted (User password used/matched for access)"
                elif decryption_status_code == 2:
                    pdf_meta['encryption_status'] = "Encrypted (Owner password used/matched; content accessible)"
                else: 
                    pdf_meta['encryption_status'] = f"Encrypted (Unknown legacy status code: {decryption_status_code})"
            except PyPDF2LibDependencyError: 
                 pdf_meta['encryption_status'] = "Encrypted (decryption libraries like 'cryptography' might be missing)"
            except Exception as e_decrypt:
                 pdf_meta['encryption_status'] = f"Encrypted (error during decryption check: {str(e_decrypt)})"
        
        for page in reader.pages[:min(len(reader.pages), 3)]: 
            if extracted_text := page.extract_text(): 
                text_content += extracted_text + "\n"
        if text_content:
            found_keywords = [term for term in ["confidential", "password", "invoice", "secret", "bank account", "credit card"] if term.lower() in text_content.lower()]
            if found_keywords: pdf_meta['keywords_detected'] = ", ".join(found_keywords)
            
    except Exception as e: pdf_meta['pdf_error'] = f"PDF read error: {str(e)}"
    return pdf_meta

def get_ole_metadata(ole_path):
    ole_meta = {}
    try:
        if olefile.isOleFile(ole_path):
            ole = olefile.OleFileIO(ole_path); meta = ole.get_metadata()
            if meta:
                for prop in ['author', 'title', 'subject', 'comments', 'keywords', 'last_saved_by', 'company', 'manager', 'codepage', 'version', 'create_time', 'last_saved_time', 'num_pages', 'num_words']:
                    val = getattr(meta, prop, None)
                    if val: ole_meta[f"ole_{prop}"] = val.decode('utf-8', 'replace') if isinstance(val, bytes) else str(val)
            ole.close()
    except Exception as e: ole_meta['ole_error'] = f"OLE read error: {str(e)}"
    return ole_meta

INVESTIGATIVE_FRAMEWORKS = {
    "Phishing": [
        "<b>Phase 1: Identification & Initial Analysis</b>",
        "  - Obtain the original phishing email (.eml or .msg format if possible).",
        "  - Analyze email headers: Examine `Return-Path`, `Received` hops, `X-Originating-IP`, `Authentication-Results` (SPF, DKIM, DMARC).",
        "  - Identify sender's purported identity vs. actual sending address/domain.",
        "  - Check sender domain reputation (WHOIS, DNS records, blacklist services like Spamhaus, VirusTotal).",
        "  - Analyze email body for suspicious language, urgency, grammatical errors, and unusual requests.",
        "  - Hover over all links to see actual destination URLs. Check for typosquatting, URL shorteners, or mismatched display text.",
        "<b>Phase 2: Payload/Link Analysis</b>",
        "  - If Links: DO NOT CLICK directly. Use a URL scanning service (VirusTotal, URLScan.io) or a safe browsing environment (VM, browser sandbox).",
        "  - Analyze redirection chains if any.",
        "  - If it leads to a login page, check for signs of a credential harvesting site (non-HTTPS, suspicious domain, poorly cloned page).",
        "  - If Attachments: DO NOT OPEN directly. Submit to a sandbox environment (e.g., Any.Run, Hybrid Analysis, local Cuckoo Sandbox) or use static/dynamic malware analysis tools.",
        "  - Identify file type and hash (MD5, SHA256). Check hash against threat intelligence feeds.",
        "<b>Phase 3: Impact Assessment & Scope</b>",
        "  - Determine if the recipient interacted with the email (clicked links, opened attachments, replied, provided credentials).",
        "  - Check logs (email gateway, web proxy, endpoint) for other recipients of the same/similar phishing email.",
        "  - If credentials compromised, immediately initiate password reset procedures for affected accounts and any other accounts using same credentials.",
        "  - Scan potentially affected endpoints for malware if attachments were opened.",
        "<b>Phase 4: Containment, Eradication & Recovery</b>",
        "  - Block sender email address, domain, and any identified malicious IPs/URLs at email gateway/firewall/proxy.",
        "  - Delete phishing emails from all affected mailboxes (if enterprise-wide tools are available).",
        "  - If accounts were compromised, review for unauthorized activity and remediate.",
        "  - If malware was deployed, follow malware eradication procedures.",
        "<b>Phase 5: Post-Incident & Lessons Learned</b>",
        "  - Document the incident thoroughly.",
        "  - Report the phishing attempt to relevant authorities or services (e.g., Anti-Phishing Working Group, Google Safe Browsing).",
        "  - Update user awareness training with examples from the incident.",
        "  - Review and enhance email filtering rules and security controls."
    ],
    "Malware/Ransomware": [
        "<b>Phase 1: Preparation (Ongoing)</b>",
        "  - Ensure up-to-date backups (tested regularly), incident response plan, and contact lists.",
        "  - Deploy EDR/XDR, robust AV, network monitoring, and SIEM.",
        "<b>Phase 2: Identification</b>",
        "  - Initial Indicators: User reports, AV/EDR alerts, unusual system behavior (slowness, pop-ups, encrypted files, ransom note).",
        "  - Verify Infection: Confirm malware presence. Isolate a sample if possible for analysis.",
        "  - Malware Type: Determine if it's ransomware, trojan, worm, spyware, etc. Note specific family if identifiable.",
        "  - Infection Vector: How did it get in? (Email attachment, malicious link, unpatched vulnerability, compromised credentials, infected removable media).",
        "<b>Phase 3: Containment</b>",
        "  - Isolate Affected Systems: Disconnect from network (unplug Ethernet, disable Wi-Fi) to prevent spread. Do NOT turn off if memory forensics is planned immediately.",
        "  - Identify C2: Block communication to known Command & Control servers at firewall/proxy.",
        "  - Account Lockout: Disable compromised user accounts if applicable.",
        "  - Network Segmentation: If not already in place, consider if temporary segmentation can limit spread.",
        "<b>Phase 4: Eradication</b>",
        "  - Remove Malware: Use trusted AV/anti-malware tools from a safe boot environment if necessary. Consider re-imaging severely infected systems.",
        "  - Patch Vulnerabilities: Address the initial infection vector (e.g., patch software, update configurations).",
        "  - Remove Persistence Mechanisms: Check registry keys, scheduled tasks, startup folders for malware persistence.",
        "<b>Phase 5: Recovery</b>",
        "  - Restore Data: Restore affected files/systems from clean, verified backups. Prioritize critical systems.",
        "  - Verify System Integrity: Ensure systems are clean before reconnecting to the network.",
        "  - Change Credentials: Reset all passwords for accounts on or related to affected systems.",
        "  - Monitor: Closely monitor restored systems for any signs of reinfection or unusual activity.",
        "<b>Phase 6: Post-Incident Activity (Lessons Learned)</b>",
        "  - Document all actions, findings, and timelines.",
        "  - Conduct a root cause analysis.",
        "  - Update IR plan, security policies, and user training.",
        "  - Report to authorities if required (e.g., for ransomware affecting critical data/services)."
    ],
    "Data Breach": [
        "<b>Phase 1: Preparation (Ongoing)</b>",
        "  - Data classification, asset inventory, robust logging and monitoring, IR plan.",
        "<b>Phase 2: Identification & Initial Assessment</b>",
        "  - Detection: How was the breach detected (internal alert, external notification, user report)?",
        "  - Initial Verification: Confirm that a breach has occurred. Avoid actions that could corrupt evidence.",
        "  - Assemble IR Team: Activate the incident response team and assign roles.",
        "  - Initial Scope: What systems/data are known to be affected? What is the potential impact?",
        "<b>Phase 3: Containment</b>",
        "  - Isolate Affected Segments: Prevent further data exfiltration or unauthorized access. This might involve disconnecting systems, blocking IPs, disabling accounts.",
        "  - Preserve Evidence: Take forensic images of affected systems, collect relevant logs (network, server, application, security devices), network captures.",
        "  - Identify Attacker Presence: Determine if the attacker is still active in the environment.",
        "<b>Phase 4: Eradication</b>",
        "  - Identify Root Cause: Determine the vulnerabilities or methods used by the attacker (e.g., malware, exploited vulnerability, compromised credentials, insider threat).",
        "  - Remove Attacker Artifacts: Eliminate malware, backdoors, and any attacker tools.",
        "  - Remediate Vulnerabilities: Patch systems, strengthen configurations, reset compromised credentials.",
        "<b>Phase 5: Recovery</b>",
        "  - Restore Systems: Restore affected systems and data from clean backups or rebuild them.",
        "  - Validate Systems: Ensure systems are clean and functioning correctly before bringing them fully online.",
        "  - Monitor: Implement enhanced monitoring for affected systems and the environment for any signs of attacker return or related activity.",
        "<b>Phase 6: Post-Incident Activity & Notification</b>",
        "  - Detailed Investigation & Analysis: Full forensic analysis of collected evidence to understand the complete attack lifecycle.",
        "  - Notification Strategy: Determine legal and regulatory notification obligations (data protection authorities, affected individuals, law enforcement).",
        "  - Execute Notifications: Send out required notifications within stipulated timeframes.",
        "  - Public Relations: Manage communications with media and public if necessary.",
        "  - Lessons Learned: Conduct a thorough review, update policies, procedures, technical controls, and training. Document everything."
        ],
    "Online Harassment/Cyberbullying": [
        "<b>Phase 1: Evidence Preservation & Initial Assessment</b>",
        "  - Preserve Evidence: Take screenshots/recordings of all harassing content (messages, posts, profiles, comments). Include timestamps and URLs.",
        "  - Document Details: Note dates, times, platforms, usernames of aggressors, and nature of harassment.",
        "  - Assess Severity & Risk: Is there an immediate threat to safety? Are specific laws being broken (e.g., hate speech, defamation, threats)?",
        "<b>Phase 2: Reporting & Support</b>",
        "  - Report to Platform: Use the platform's reporting tools to report the abusive content and users. Provide collected evidence.",
        "  - Block & Adjust Privacy: Advise the victim to block the aggressor(s) and review/strengthen privacy settings on all relevant accounts.",
        "  - Offer Support: Provide resources for emotional support (counseling, support groups). Emphasize they are not alone.",
        "<b>Phase 3: Further Action (If Necessary)</b>",
        "  - Law Enforcement: If harassment involves credible threats, stalking, child exploitation, or other illegal activities, report to local law enforcement. Provide all documented evidence.",
        "  - School/Workplace: If harassment is related to a school or workplace, report to the relevant authorities there according to their policies.",
        "  - Legal Counsel: In cases of severe defamation or ongoing harassment impacting reputation or safety, advise seeking legal counsel.",
        "<b>Phase 4: Monitoring & Follow-up</b>",
        "  - Monitor Situation: Check if harassment continues after initial actions. Document any further incidents.",
        "  - Follow Up: Follow up with platforms or authorities on reported incidents.",
        "  - Digital Hygiene: Advise on ongoing good digital hygiene practices to minimize future risks."
    ],
    "Account Compromise": [
        "<b>Phase 1: Immediate Response & Containment</b>",
        "  - Password Reset: Immediately change the password of the compromised account to a strong, unique one.",
        "  - Enable MFA: If not already enabled, turn on Multi-Factor Authentication for the account.",
        "  - Review Security Settings: Check for suspicious recovery email/phone changes, connected apps, or forwarding rules.",
        "  - Revoke Active Sessions: If the platform allows, sign out of all active sessions for the account.",
        "  - Isolate Device (if suspected malware): If the compromise is suspected to be due to malware on a device, isolate that device from the network.",
        "<b>Phase 2: Investigation & Scope</b>",
        "  - Review Activity Logs: Examine login history, IP addresses, recent activities (sent emails, file access/changes, financial transactions) for unauthorized actions.",
        "  - Identify Compromise Vector: How was the account compromised? (Phishing, malware, weak/reused password, data breach elsewhere, social engineering).",
        "  - Assess Impact: What data or access was gained? Were other accounts or systems affected?",
        "  - Scan Devices: Scan all devices used to access the account for malware.",
        "<b>Phase 3: Eradication & Recovery</b>",
        "  - Address Root Cause: If malware, remove it. If phishing, identify and educate. If vulnerability, patch it.",
        "  - Secure Related Accounts: Change passwords for any other accounts that might have used the same or similar credentials.",
        "  - Notify Contacts (if necessary): If the compromised account was used to send malicious messages, inform contacts to be wary.",
        "  - Restore Data (if applicable): If data was altered or deleted, restore from backups.",
        "<b>Phase 4: Post-Incident & Prevention</b>",
        "  - Document Incident: Record all findings and actions taken.",
        "  - User Education: Reinforce strong password practices, MFA usage, and phishing awareness.",
        "  - Review Access Controls: Ensure least privilege principles are applied.",
        "  - Monitor: Continue to monitor the account and related systems for any suspicious activity."
    ],
    "Denial of Service (DoS)": [
        "<b>Phase 1: Identification & Verification</b>",
        "  - Symptoms: Slowness, unavailability of a service/website, high network traffic, server resource exhaustion.",
        "  - Verify Attack: Differentiate from legitimate high traffic or other outages. Use network monitoring tools, server logs.",
        "  - Identify Target: Determine the specific IP addresses, ports, or services being targeted.",
        "  - Characterize Attack: Is it volumetric (bandwidth exhaustion), protocol-based (exploiting protocol weaknesses), or application-layer (overwhelming application resources)? Is it DoS (single source) or DDoS (multiple sources)?",
        "<b>Phase 2: Containment & Mitigation</b>",
        "  - Traffic Filtering: Implement ACLs on routers/firewalls to block traffic from identified malicious source IPs (less effective for DDoS).",
        "  - Rate Limiting: Configure servers or network devices to limit the number of requests from a single IP over a period.",
        "  - ISP/Hosting Provider: Contact your ISP or hosting provider. They may have DDoS mitigation services or be able to null-route traffic.",
        "  - DDoS Mitigation Service: If subscribed, activate or escalate to your DDoS mitigation provider (e.g., Cloudflare, Akamai, AWS Shield).",
        "  - Load Balancing/Auto-Scaling: If applicable, ensure these systems are functioning to distribute load.",
        "  - Firewall/WAF Tuning: Adjust rules to block common DoS attack patterns or known malicious signatures.",
        "<b>Phase 3: Recovery & Normalization</b>",
        "  - Monitor Traffic: Continuously monitor network traffic and service availability to ensure the attack has subsided and mitigation is effective.",
        "  - Gradual Service Restoration: Bring services back online carefully, monitoring for re-attacks.",
        "  - Remove Temporary Filters: Once stable, review and remove any overly restrictive temporary filters if they impact legitimate traffic.",
        "<b>Phase 4: Post-Incident Analysis & Prevention</b>",
        "  - Document the Attack: Record attack vectors, source IPs (if known), duration, impact, and mitigation steps.",
        "  - Root Cause Analysis (if applicable): Was an application vulnerability exploited?",
        "  - Strengthen Defenses: Consider CDN, dedicated DDoS protection, WAF, network infrastructure upgrades.",
        "  - Update IR Plan: Refine DoS/DDoS response procedures based on lessons learned."
    ],
    "Identity Theft": [
        "<b>Phase 1: Immediate Actions & Reporting</b>",
        "  - Contact Fraud Departments: Notify fraud departments of companies where fraud occurred (banks, credit card issuers, utilities). Close unauthorized accounts.",
        "  - Credit Bureaus: Place a fraud alert with one of the three major credit bureaus (Equifax, Experian, TransUnion). This will prompt the others to do the same. Consider a credit freeze.",
        "  - File Police Report: File a report with your local police department. Get a copy of the report, as it's crucial for disputing fraudulent debts.",
        "  - Report to FTC (US): File a complaint with the Federal Trade Commission at IdentityTheft.gov. This creates a recovery plan.",
        "<b>Phase 2: Secure Accounts & Information</b>",
        "  - Change Passwords & PINs: For all online accounts, especially financial, email, and social media. Use strong, unique passwords.",
        "  - Enable MFA: Implement Multi-Factor Authentication wherever available.",
        "  - Review Credit Reports: Obtain free copies of your credit reports from all three bureaus (e.g., via AnnualCreditReport.com) and review for any suspicious activity or accounts you didn't open.",
        "  - Review Financial Statements: Scrutinize bank and credit card statements for unauthorized transactions.",
        "<b>Phase 3: Dispute & Recover</b>",
        "  - Dispute Fraudulent Debts: Send letters (certified mail, return receipt requested) to businesses and debt collectors regarding fraudulent accounts or charges. Include a copy of your police report and FTC affidavit.",
        "  - Address Misused Information: If your SSN was misused, contact the Social Security Administration. If tax fraud, contact the IRS. If medical identity theft, contact healthcare providers and insurers.",
        "  - Correct Credit Reports: Follow up with credit bureaus to ensure fraudulent information is removed from your reports.",
        "<b>Phase 4: Ongoing Monitoring & Prevention</b>",
        "  - Monitor Regularly: Continue to monitor your credit reports, financial statements, and mail for any new signs of fraud.",
        "  - Secure Personal Information: Shred sensitive documents, be cautious about sharing personal information, use secure internet connections.",
        "  - Consider Identity Theft Protection Services: Evaluate if a paid service is beneficial for ongoing monitoring and recovery assistance."
    ],
    "Financial Fraud": [
        "<b>Phase 1: Immediate Containment & Notification</b>",
        "  - Contact Financial Institution(s): Immediately notify the bank, credit card company, payment platform, or other institution where the fraud occurred. Request to freeze or close affected accounts/cards.",
        "  - Dispute Unauthorized Transactions: Follow the institution's process for disputing fraudulent charges.",
        "  - Change Passwords/PINs: Immediately change passwords, PINs, and security questions for the affected financial accounts and any linked accounts (especially email).",
        "  - Enable MFA: Ensure Multi-Factor Authentication is enabled on all financial accounts.",
        "<b>Phase 2: Evidence Collection & Documentation</b>",
        "  - Gather All Records: Collect statements, transaction details, dates, times, amounts, and any communications related to the fraud (emails, messages, call logs).",
        "  - Note How Fraud Was Discovered: Document when and how you became aware of the fraudulent activity.",
        "  - Preserve Digital Evidence: If the fraud involved online interaction, save screenshots, URLs, and any digital artifacts.",
        "<b>Phase 3: Reporting to Authorities</b>",
        "  - File a Police Report: Report the fraud to your local law enforcement agency. Obtain a copy of the police report.",
        "  - Report to Regulatory Bodies: Depending on the type of fraud and jurisdiction, report to relevant consumer protection agencies or financial regulators (e.g., FTC in the US, Action Fraud in the UK, Canadian Anti-Fraud Centre).",
        "  - Report to Other Relevant Parties: If the fraud involved specific services (e.g., online marketplaces, wire transfer services), report it to them as well.",
        "<b>Phase 4: Monitoring & Recovery</b>",
        "  - Monitor Accounts Closely: Regularly review all financial accounts for any further suspicious activity.",
        "  - Review Credit Reports: Check your credit reports from all major bureaus for any unauthorized accounts or inquiries.",
        "  - Work with Institutions: Follow up with financial institutions on disputed transactions and account recovery.",
        "  - Implement Security Measures: Scan devices for malware. Be cautious of phishing attempts. Review and strengthen online security practices.",
        "<b>Phase 5: Lessons Learned</b>",
        "  - Analyze How Fraud Occurred: Try to determine the root cause (e.g., compromised credentials, phishing, malware, social engineering).",
        "  - Educate & Share: If applicable, share lessons learned with family or colleagues to prevent similar incidents."
    ],
    "Other": [
        "<b>1. Clarify & Gather Details:</b> Understand the nature of the 'Other' incident. What are the key observations? What is the perceived impact? Who is affected? When did it start?",
        "<b>2. Initial Categorization Attempt:</b> Based on details, try to map it to a known incident type or a combination. Is it a security, privacy, operational, or legal issue primarily?",
        "<b>3. Preserve All Potential Evidence:</b> Immediately secure any related logs (system, network, application), screenshots, emails, physical items, configurations, or witness statements. Document the state of affected systems if possible (e.g., memory dump, disk image if critical).",
        "<b>4. Initial Triage & Risk Assessment:</b> Determine urgency based on potential impact (financial, reputational, operational, legal, safety). Is there ongoing damage or immediate risk? Prioritize actions accordingly.",
        "<b>5. Consult Subject Matter Experts (SMEs):</b> If the incident is technical, legal, or complex, involve relevant IT/security specialists, legal counsel, HR, or other departmental experts early.",
        "<b>6. Containment (if applicable & safe to do so):</b> If there's an active threat or ongoing damage, take steps to limit its impact after consulting SMEs (e.g., isolate a system, block an account, disable a service). Ensure containment actions don't destroy critical evidence.",
        "<b>7. Documentation:</b> Maintain a detailed, chronological log of all observations, decisions made, actions taken, individuals involved, and communications. This is crucial for post-incident review and potential legal proceedings.",
        "<b>8. Escalate & Communicate:</b> If the incident is potentially severe or beyond local capability to handle, escalate to appropriate levels of management (IT, security, legal, executive). Establish clear communication channels for the incident response team and stakeholders.",
        "<b>9. Follow General Incident Response Lifecycle:</b> Adapt the standard Identification, Containment, Eradication, Recovery, and Lessons Learned phases to the specifics of the unique incident. The SANS/NIST frameworks provide good general guidance.",
        "<b>10. Post-Incident Review:</b> Once resolved, conduct a thorough review to understand the root cause, the effectiveness of the response, and identify improvements for policies, procedures, and controls."
    ]
}

def generate_incident_pdf_report(incident_report, forensic_data=None):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    styles = getSampleStyleSheet()
    
    custom_styles = {
        'ReportTitle': ParagraphStyle(name='ReportTitle', fontSize=18, alignment=TA_CENTER, spaceBottom=18, textColor=colors.HexColor("#003366"), fontName='Helvetica-Bold'),
        'SectionHeader': ParagraphStyle(name='SectionHeader', fontSize=13, alignment=TA_LEFT, spaceBefore=10, spaceBottom=5, textColor=colors.HexColor("#004085"), fontName='Helvetica-Bold'),
        'SubHeader': ParagraphStyle(name='SubHeader', fontSize=10, alignment=TA_LEFT, spaceBefore=6, spaceBottom=3, textColor=colors.HexColor("#333333"), fontName='Helvetica-Bold'),
        'Justify': ParagraphStyle(name='Justify', alignment=TA_JUSTIFY, parent=styles['Normal'], spaceBefore=2, spaceAfter=2, leading=12),
        'ForensicKey': ParagraphStyle(name='ForensicKey', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=9),
        'ForensicValue': ParagraphStyle(name='ForensicValue', parent=styles['Normal'], leftIndent=10, fontSize=9, leading=11),
        'ListItem': ParagraphStyle(name='ListItem', parent=styles['Normal'], leftIndent=18, spaceBefore=3, firstLineIndent=-10, bulletIndent=0, fontSize=9, leading=11), 
        'FrameworkStep': ParagraphStyle(name='FrameworkStep', parent=styles['Normal'], leftIndent=18, spaceBefore=3, fontSize=9, leading=11, spaceAfter=2)
    }
    for name, style_obj in custom_styles.items():
        if name not in styles: styles.add(style_obj)
        else: styles[name] = style_obj

    story = []
    story.append(Paragraph("Cyber Incident Forensic Summary", styles['ReportTitle']))
    story.append(Spacer(1, 0.1 * 72))

    story.append(Paragraph("Incident Details", styles['SectionHeader']))
    incident_data_table_content = [
        [Paragraph("Report ID:", styles['ForensicKey']), Paragraph(str(incident_report.id), styles['ForensicValue'])],
        [Paragraph("Timestamp:", styles['ForensicKey']), Paragraph(incident_report.timestamp.strftime('%Y-%m-%d %H:%M:%S') if incident_report.timestamp else "N/A", styles['ForensicValue'])],
        [Paragraph("Reporter IP:", styles['ForensicKey']), Paragraph(incident_report.reporter_ip if incident_report.reporter_ip else "N/A", styles['ForensicValue'])],
        [Paragraph("Incident Type:", styles['ForensicKey']), Paragraph(incident_report.incident_type, styles['ForensicValue'])],
        [Paragraph("Reporter Name:", styles['ForensicKey']), Paragraph(incident_report.reporter_name if incident_report.reporter_name else "N/A", styles['ForensicValue'])],
        [Paragraph("Reporter Email:", styles['ForensicKey']), Paragraph(incident_report.reporter_email if incident_report.reporter_email else "N/A", styles['ForensicValue'])],
        [Paragraph("Reporter Phone:", styles['ForensicKey']), Paragraph(incident_report.reporter_phone if incident_report.reporter_phone else "N/A", styles['ForensicValue'])],
    ]
    table = Table(incident_data_table_content, colWidths=[1.5*72, 5.0*72])
    table.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 0.5, colors.lightgrey), ('VALIGN', (0,0), (-1,-1), 'TOP'), ('LEFTPADDING', (0,0), (-1,-1), 3), ('BOTTOMPADDING', (0,0), (-1,-1), 5)]))
    story.append(table); story.append(Spacer(1, 0.1 * 72))
    story.append(Paragraph("Description:", styles['SubHeader']))
    story.append(Paragraph(incident_report.description.replace('\r\n', '\n').replace('\r', '\n'), styles['Justify']))
    story.append(Spacer(1, 0.2 * 72))

    if incident_report.evidence:
        story.append(Paragraph("Evidence File Forensic Insights", styles['SectionHeader']))
        if forensic_data and not forensic_data.get('error'):
            story.append(Paragraph(f"File Name: {forensic_data.get('file_name', 'N/A')}", styles['SubHeader']))
            if forensic_data.get('file_type_mime','').startswith('image/'):
                try:
                    img_path = os.path.join(current_app.root_path, incident_report.evidence)
                    if os.path.exists(img_path): story.append(RLImage(img_path, width=2*72, height=2*72, hAlign='CENTER')); story.append(Spacer(1,6))
                except: pass 
            
            fdata_table = []
            preferred = ['file_type_mime', 'file_size_bytes', 'signature_match', 'shannon_entropy', 'entropy_analysis', 'is_encrypted', 'encryption_status', 'keywords_detected', 'steganography_lsb_hint', 'dimensions', 'format', 'last_modified', 'created_time']
            for k in preferred:
                if k in forensic_data and forensic_data[k] is not None:
                    v = str(forensic_data[k]); v = (v[:97] + '...') if len(v) > 100 else v
                    fdata_table.append([Paragraph(k.replace('_',' ').title(), styles['ForensicKey']), Paragraph(v, styles['ForensicValue'])])
            for k, v_raw in forensic_data.items():
                if k not in preferred and v_raw is not None and k not in ['file_name', 'error', 'extraction_error', 'exif_error', 'pdf_error', 'ole_error']:
                    v = str(v_raw); v = (v[:97] + '...') if len(v) > 100 else v
                    fdata_table.append([Paragraph(k.replace('_',' ').title(), styles['ForensicKey']), Paragraph(v, styles['ForensicValue'])])
            if fdata_table:
                ft = Table(fdata_table, colWidths=[2*72, 4.5*72]); ft.setStyle(TableStyle([('GRID', (0,0), (-1,-1), 0.25, colors.grey), ('VALIGN', (0,0), (-1,-1), 'TOP'), ('LEFTPADDING', (0,0), (-1,-1), 3), ('BOTTOMPADDING', (0,0), (-1,-1), 3)]))
                story.append(ft)
            else: story.append(Paragraph("No detailed metadata extracted.", styles['Normal']))
            for ek in ['extraction_error', 'exif_error', 'pdf_error', 'ole_error', 'file_read_error']:
                if forensic_data.get(ek): story.append(Paragraph(f"Note: {forensic_data[ek]}", styles['Italic']))
        elif forensic_data and forensic_data.get('error'): story.append(Paragraph(f"File Error: {forensic_data['error']}", styles['Normal']))
        else: story.append(Paragraph("No forensic data processed.", styles['Normal']))
    else: story.append(Paragraph("No evidence file.", styles['Normal']))
    
    story.append(PageBreak())
    story.append(Paragraph("Suggested Investigative Framework: " + incident_report.incident_type, styles['SectionHeader']))
    framework_steps_for_incident = INVESTIGATIVE_FRAMEWORKS.get(incident_report.incident_type, INVESTIGATIVE_FRAMEWORKS["Other"]) 
    
    current_phase_style = styles['SubHeader'] 
    step_style = styles['FrameworkStep']     

    for step_html in framework_steps_for_incident: 
        step_text_for_pdf = step_html.replace("<b>", "<font name='Helvetica-Bold'>").replace("</b>", "</font>")
        
        is_phase_title = "<b>" in step_html 

        if is_phase_title:
            phase_title = step_text_for_pdf 
            story.append(Paragraph(phase_title, current_phase_style))
        else: 
            clean_step = step_text_for_pdf.lstrip()
            if clean_step.startswith("- "):
                clean_step = clean_step[2:]
            
            clean_step = re.sub(r"^\s*\d+\.\s*", "", clean_step) 
            
            story.append(Paragraph(f"•  {clean_step.lstrip()}", step_style))
        story.append(Spacer(1, 2)) 
    story.append(Spacer(1, 0.2 * 72))
    
    story.append(Paragraph("Analyst Notes:", styles['SubHeader']))
    story.append(Spacer(1, 2 * 72))
    story.append(Paragraph("Signature: _________________________ Date: ____________", styles['Normal']))

    doc.build(story)
    buffer.seek(0)
    return buffer