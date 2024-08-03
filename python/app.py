from flask import Flask, request, render_template, send_file
from fpdf import FPDF
import requests
import socket
from urllib.parse import urlparse
import re
import dns.resolver

app = Flask(__name__)

# Hardcoded lists for demonstration purposes
PHISHING_DOMAINS = ["phishingsite.com", "fakebank.com"]
WEAK_PASSWORDS = ["123456", "password", "123456789", "qwerty", "abc123", "password1"]
MALWARE_SIGNATURES = ["trojan", "ransomware", "virus", "malware", "exploit", "backdoor", "shell", "cryptominer"]
TROJAN_INDICATORS = ["trojan", "backdoor", "malicious", "suspicious"]
SPYWARE_INDICATORS = ["spyware", "track", "monitor", "keylogger", "logger"]
CODE_INJECTION_PATTERNS = ["exec(", "eval(", "system(", "shell_exec(", "passthru(", "popen(", "proc_open(", "assert(", "include(", "require("]
URL_MANIPULATION_PATTERNS = ["id=", "user=", "name=", "value=", "redirect=", "lang=", "page="]
XXE_PAYLOADS = [
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://example.com/malicious.dtd">]><foo>&xxe;</foo>'
]
VIRUS_SIGNATURES = ["malware", "virus", "ransomware", "trojan", "worm", "exploit"]

def get_domain_from_url(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc

def check_open_redirect(url):
    try:
        response = requests.get(url, allow_redirects=True)
        return len(response.history) > 1
    except Exception as e:
        print(f"Error checking open redirect: {e}")
        return False

def check_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers
        required_headers = [
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection"
        ]
        missing_headers = [header for header in required_headers if header not in headers]
        return len(missing_headers) == 0
    except Exception as e:
        print(f"Error checking security headers: {e}")
        return False

def check_sql_injection(url):
    test_payloads = ["' OR '1'='1", '" OR "1"="1', "' OR '1'='1' --", '" OR 1=1 --']
    for payload in test_payloads:
        try:
            response = requests.get(url + payload)
            if "SQL syntax" in response.text or "error" in response.text.lower():
                return True
        except Exception as e:
            print(f"Error checking SQL Injection: {e}")
    return False

def brute_force_login(url, usernames, passwords):
    for username in usernames:
        for password in passwords:
            data = {
                'username': username,
                'password': password
            }
            try:
                response = requests.post(url, data=data)
                if "incorrect" not in response.text.lower():
                    return True, username, password
            except Exception as e:
                print(f"Error during brute force attack: {e}")
    return False, None, None

def scan_open_ports(domain, ports):
    open_ports = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            result = s.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
    return open_ports

def check_xss(url):
    xss_payloads = [
        '<script>alert("XSS")</script>',
        '"><img src="x" onerror="alert(\'XSS\')">',
        '"><svg/onload=alert("XSS")>'
    ]
    for payload in xss_payloads:
        try:
            response = requests.get(url + payload)
            if payload in response.text:
                return True
        except Exception as e:
            print(f"Error checking XSS: {e}")
    return False

def check_phishing(url):
    domain = get_domain_from_url(url)
    
    if domain in PHISHING_DOMAINS:
        return True

    phishing_keywords = ["login", "account", "verify", "update", "password"]
    try:
        response = requests.get(url)
        content = response.text.lower()
        if any(keyword in content for keyword in phishing_keywords):
            return True
    except Exception as e:
        print(f"Error checking phishing: {e}")
    
    return False

def simulate_ransomware(url):
    ransom_notes = [
        "Your files are encrypted!",
        "Pay us to decrypt your files!",
        "Ransom note: pay to get your data back!"
    ]
    try:
        response = requests.get(url)
        content = response.text.lower()
        if any(note.lower() in content for note in ransom_notes):
            return True
    except Exception as e:
        print(f"Error checking ransomware: {e}")
    
    return False

def check_weak_passwords(url):
    try:
        response = requests.get(url)
        content = response.text
        for password in WEAK_PASSWORDS:
            if re.search(rf'\b{re.escape(password)}\b', content):
                return True
    except Exception as e:
        print(f"Error checking weak passwords: {e}")
    return False

def detect_dns_tunneling(domain):
    try:
        for length in range(30, 60, 5):
            query = "A" * length + "." + domain
            response = dns.resolver.resolve(query, 'A')
            if response:
                return True
    except Exception as e:
        print(f"Error checking DNS tunneling: {e}")
    return False

def check_session_hijacking(url):
    try:
        response = requests.get(url)
        cookies = response.cookies
        for cookie in cookies:
            if not (cookie.secure and cookie.httpOnly):
                return True
        if re.search(r'session_id=[\w-]+', response.url):
            return True
    except Exception as e:
        print(f"Error checking session hijacking: {e}")
    return False

def check_cryptojacking(url):
    try:
        response = requests.get(url)
        content = response.text.lower()
        mining_scripts = ["crypto", "miner", "coinhive", "jscoin", "webminer"]
        if any(script in content for script in mining_scripts):
            return True
    except Exception as e:
        print(f"Error checking cryptojacking: {e}")
    return False

def check_drive_by(url):
    try:
        response = requests.get(url)
        content = response.text.lower()
        malicious_patterns = [
            "eval(", "document.write(", "innerHTML=", "setTimeout(", "setInterval(", "location.replace(", "iframe src="
        ]
        if any(pattern in content for pattern in malicious_patterns):
            return True
    except Exception as e:
        print(f"Error checking drive-by attacks: {e}")
    return False

def check_malware(url):
    try:
        response = requests.get(url)
        content = response.text.lower()
        if any(signature in content for signature in MALWARE_SIGNATURES):
            return True
    except Exception as e:
        print(f"Error checking malware: {e}")
    return False

def check_csrf(url):
    try:
        response = requests.get(url)
        content = response.text
        forms_without_tokens = re.findall(r'<form\b[^>]*>', content)
        csrf_patterns = [
            'csrf', 'token', 'security', 'xsrf'
        ]
        for form in forms_without_tokens:
            if not any(pattern in form.lower() for pattern in csrf_patterns):
                return True
    except Exception as e:
        print(f"Error checking CSRF: {e}")
    return False

def check_directory_traversal(url):
    test_payloads = [
        '/../etc/passwd', '/../../etc/passwd', '../admin/config.php', '/../../../../var/www/html/index.php'
    ]
    for payload in test_payloads:
        try:
            response = requests.get(url + payload)
            if response.status_code == 200 and 'No such file' not in response.text:
                return True
        except Exception as e:
            print(f"Error checking Directory Traversal: {e}")
    return False

def check_trojans(url):
    try:
        response = requests.get(url)
        content = response.text.lower()
        if any(indicator in content for indicator in TROJAN_INDICATORS):
            return True
    except Exception as e:
        print(f"Error checking Trojans: {e}")
    return False

def check_spyware(url):
    try:
        response = requests.get(url)
        content = response.text.lower()
        if any(indicator in content for indicator in SPYWARE_INDICATORS):
            return True
    except Exception as e:
        print(f"Error checking Spyware: {e}")
    return False

def check_code_injection(url):
    try:
        response = requests.get(url)
        content = response.text.lower()
        if any(pattern in content for pattern in CODE_INJECTION_PATTERNS):
            return True
    except Exception as e:
        print(f"Error checking Code Injection: {e}")
    return False

def check_url_manipulation(url):
    try:
        response = requests.get(url)
        content = response.text.lower()
        if any(pattern in content for pattern in URL_MANIPULATION_PATTERNS):
            return True
    except Exception as e:
        print(f"Error checking URL Manipulation: {e}")
    return False

def check_xxe(url):
    try:
        response = requests.post(url, data=XXE_PAYLOADS[0], headers={"Content-Type": "application/xml"})
        if "error" in response.text.lower():
            return True
    except Exception as e:
        print(f"Error checking XXE: {e}")
    return False

def get_detection_status(result):
    return "Vulnerable" if result else "Not Vulnerable"

def get_severity(result):
    return "High" if result else "N/A"

def get_recommendation(vulnerability):
    recommendations = {
        "Open Redirect": "Ensure that redirection is only allowed to trusted URLs.",
        "Security Headers": "Implement missing security headers.",
        "SQL Injection": "Sanitize and parameterize all user inputs.",
        "Brute Force Login": "Implement account lockout mechanisms and CAPTCHAs.",
        "Open Ports": "Close unused ports and use firewalls.",
        "XSS": "Escape user input and validate data.",
        "Phishing": "Verify domain legitimacy and educate users.",
        "Ransomware": "Regularly back up data and use security software.",
        "Weak Passwords": "Enforce strong password policies.",
        "DNS Tunneling": "Monitor and restrict DNS queries.",
        "Session Hijacking": "Use secure cookies and implement session management.",
        "Cryptojacking": "Detect and remove mining scripts.",
        "Drive-By Attack": "Use up-to-date security patches and scan for malicious scripts.",
        "Malware": "Regularly scan for and remove malware.",
        "CSRF": "Implement CSRF tokens in forms.",
        "Directory Traversal": "Sanitize and validate file paths.",
        "Trojans": "Use antivirus software and scan for malicious files.",
        "Spyware": "Use security tools to detect and remove spyware.",
        "Code Injection": "Validate and sanitize all inputs.",
        "URL Manipulation": "Implement input validation and authorization checks.",
        "XXE": "Disable XML external entity processing."
    }
    return recommendations.get(vulnerability, "No recommendation available.")

def generate_pdf_report(results):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    pdf.cell(200, 10, txt="Vulnerability Scan Report", ln=True, align='C')
    pdf.ln(10)

    # Table header
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(30, 10, 'Vulnerability', 1)
    pdf.cell(30, 10, 'Status', 1)
    pdf.cell(30, 10, 'Severity', 1)
    pdf.cell(0, 10, 'Recommendation', 1, ln=True)

    # Table content
    pdf.set_font("Arial", size=10)
    for section, (status, severity, recommendation) in results.items():
        pdf.cell(30, 5, section, 1)
        pdf.cell(30, 5, status, 1)
        pdf.cell(30, 5, severity, 1)
        pdf.cell(0, 5, recommendation, 1)
        pdf.ln()

    pdf_file = "vulnerability_report.pdf"
    pdf.output(pdf_file)
    return pdf_file

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        url = request.form['url']

        results = {
            "Open Redirect": (check_open_redirect(url), get_severity(check_open_redirect(url)), get_recommendation("Open Redirect")),
            "Security Headers": (check_security_headers(url), get_severity(check_security_headers(url)), get_recommendation("Security Headers")),
            "SQL Injection": (check_sql_injection(url), get_severity(check_sql_injection(url)), get_recommendation("SQL Injection")),
            "Brute Force Login": (brute_force_login(url, ["admin", "user"], ["password", "123456"])[0], get_severity(brute_force_login(url, ["admin", "user"], ["password", "123456"])[0]), get_recommendation("Brute Force Login")),
            "Open Ports": (scan_open_ports(get_domain_from_url(url), [22, 80, 443, 8080]), get_severity(scan_open_ports(get_domain_from_url(url), [22, 80, 443, 8080])), get_recommendation("Open Ports")),
            "XSS": (check_xss(url), get_severity(check_xss(url)), get_recommendation("XSS")),
            "Phishing": (check_phishing(url), get_severity(check_phishing(url)), get_recommendation("Phishing")),
            "Ransomware": (simulate_ransomware(url), get_severity(simulate_ransomware(url)), get_recommendation("Ransomware")),
            "Weak Passwords": (check_weak_passwords(url), get_severity(check_weak_passwords(url)), get_recommendation("Weak Passwords")),
            "DNS Tunneling": (detect_dns_tunneling(get_domain_from_url(url)), get_severity(detect_dns_tunneling(get_domain_from_url(url))), get_recommendation("DNS Tunneling")),
            "Session Hijacking": (check_session_hijacking(url), get_severity(check_session_hijacking(url)), get_recommendation("Session Hijacking")),
            "Cryptojacking": (check_cryptojacking(url), get_severity(check_cryptojacking(url)), get_recommendation("Cryptojacking")),
            "Drive-By Attack": (check_drive_by(url), get_severity(check_drive_by(url)), get_recommendation("Drive-By Attack")),
            "Malware": (check_malware(url), get_severity(check_malware(url)), get_recommendation("Malware")),
            "CSRF": (check_csrf(url), get_severity(check_csrf(url)), get_recommendation("CSRF")),
            "Directory Traversal": (check_directory_traversal(url), get_severity(check_directory_traversal(url)), get_recommendation("Directory Traversal")),
            "Trojans": (check_trojans(url), get_severity(check_trojans(url)), get_recommendation("Trojans")),
            "Spyware": (check_spyware(url), get_severity(check_spyware(url)), get_recommendation("Spyware")),
            "Code Injection": (check_code_injection(url), get_severity(check_code_injection(url)), get_recommendation("Code Injection")),
            "URL Manipulation": (check_url_manipulation(url), get_severity(check_url_manipulation(url)), get_recommendation("URL Manipulation")),
            "XXE": (check_xxe(url), get_severity(check_xxe(url)), get_recommendation("XXE"))
        }

        results_text = {
            key: (
                get_detection_status(value[0]),
                value[1] if value[0] else "N/A",
                value[2] if value[0] else "N/A"
            )
            for key, value in results.items()
        }

        pdf_file = generate_pdf_report(results_text)

        return render_template('results.html', results=results_text, pdf_file=pdf_file)

    return render_template('index.html')

@app.route('/download/<filename>')
def download_file(filename):
    return send_file(filename, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
