# Phishguard
PhishGuard is a web-based cybersecurity tool designed to help users determine whether a URL or website is safe to visit. It combines VirusTotal threat intelligence with advanced homoglyph and phishing detection techniques to provide a clear and reliable verdict on URL safety.

The platform evaluates URLs based on multiple layers of analysis:

VirusTotal Integration:
Checks the submitted URL against VirusTotal’s database of over 70 security vendors.
Detects URLs flagged as malicious or suspicious, giving an authoritative verdict of Likely Phishing.

Homoglyph & Mimic Detection:
Detects visually deceptive characters in domain names (e.g., gοogle.com with Cyrillic “o”, or f@cebook.com).
Includes ASCII look-alikes (@, 0, rn, vv) and Unicode characters from Greek, Cyrillic, and other scripts.
Detects Punycode (xn--) domains and mixed-script domains.
Identifies invisible or zero-width characters used to deceive users.

Verdict Logic:
Likely Phishing → VirusTotal flags the URL as malicious or suspicious.
Suspicious → No VirusTotal flags, but homoglyph/mimic patterns detected.
Legitimate → Clean according to VirusTotal and no suspicious patterns.
User-Friendly Web Interface:
Built using Flask, with a clean and responsive front-end.
Displays the URL, verdict, VirusTotal engine names (if any flagged), and reasons for suspicion.
Color-coded verdicts: green for Legitimate, orange for Suspicious, red for Likely Phishing.

Technologies Used:
Python, Flask
HTML, CSS
Requests library for API calls
VirusTotal API for threat intelligence
Unicode and regex analysis for homoglyph detection

Use Case:
PhishGuard is ideal for individuals and organizations who want to verify links before clicking, protecting against phishing attacks and URL impersonation attempts. It’s a lightweight yet powerful tool for improving online security awareness.
