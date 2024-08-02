from flask import Flask, request, render_template_string, jsonify
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode
import socket
import time

app = Flask(__name__)

# URL ko validate karne ka function
def validate_url(url):
    try:
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = "http://" + url
            parsed_url = urlparse(url)
        # Check karne ke liye ek simple request send karte hain ke URL reachable hai ya nahi
        requests.get(url, timeout=5)
        return url
    except requests.exceptions.RequestException as e:
        return None

# SQL Injection vulnerability detect karne ka function
def detect_sql_injection(url):
    sql_payloads = ["'", "' OR '1'='1", '" OR "1"="1"']
    results = []
    for payload in sql_payloads:
        payload_url = urljoin(url, f"?payload={urlencode({'payload': payload})}")
        try:
            r = requests.get(payload_url, timeout=5)
            if "syntax" in r.text.lower() or "mysql" in r.text.lower() or "sql" in r.text.lower():
                results.append(f"[!] SQL Injection vulnerability detected at {url}")
        except requests.exceptions.RequestException as e:
            results.append(f"[-] Error during SQL Injection test at {url}: {e}")
    return results

# XSS vulnerability detect karne ka function
def detect_xss(url):
    xss_payload = "<script>alert('XSS')</script>"
    results = []
    try:
        r = requests.get(url, params={"q": xss_payload}, timeout=5)
        if xss_payload in r.text:
            results.append(f"[!] XSS vulnerability detected at {url}")
    except requests.exceptions.RequestException as e:
        results.append(f"[-] Error during XSS test at {url}: {e}")
    return results

# Open Redirect vulnerability detect karne ka function
def detect_open_redirect(url):
    redirect_payloads = ["http://evil.com", "//evil.com"]
    results = []
    for payload in redirect_payloads:
        payload_url = urljoin(url, f"?next={urlencode({'next': payload})}")
        try:
            r = requests.get(payload_url, timeout=5, allow_redirects=False)
            if r.status_code in [301, 302] and "Location" in r.headers and payload in r.headers["Location"]:
                results.append(f"[!] Open Redirect vulnerability detected at {url}")
        except requests.exceptions.RequestException as e:
            results.append(f"[-] Error during Open Redirect test at {url}: {e}")
    return results

# Clickjacking vulnerability detect karne ka function
def detect_clickjacking(url):
    results = []
    try:
        r = requests.get(url, timeout=5)
        if "X-Frame-Options" not in r.headers:
            results.append(f"[!] Clickjacking vulnerability detected at {url}")
    except requests.exceptions.RequestException as e:
        results.append(f"[-] Error during Clickjacking test at {url}: {e}")
    return results

# CSRF vulnerability detect karne ka function
def detect_csrf(url):
    forms = get_all_forms(url)
    results = []
    for form in forms:
        if not form.find("input", {"type": "hidden", "name": "csrf_token"}):
            results.append(f"[!] CSRF vulnerability detected in form at {url}")
    return results

# Webpage se forms extract karne ka function
def get_all_forms(url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, "html.parser")
        return soup.find_all("form")
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during form extraction at {url}: {e}")
        return []

# Forms submit karke XSS vulnerabilities detect karne ka function
def test_xss_in_forms(url):
    forms = get_all_forms(url)
    js_script = "<script>alert('XSS')</script>"
    results = []
    for form in forms:
        action = form.attrs.get("action")
        post_url = urljoin(url, action)
        data = {}
        for input_tag in form.find_all("input"):
            input_name = input_tag.attrs.get("name")
            input_type = input_tag.attrs.get("type", "text")
            input_value = input_tag.attrs.get("value", "")
            if input_type == "text":
                input_value = js_script
            data[input_name] = input_value

        try:
            response = requests.post(post_url, data=data, timeout=5)
            if js_script in response.text:
                results.append(f"[!] XSS vulnerability detected in form at {post_url}")
        except requests.exceptions.RequestException as e:
            results.append(f"[-] Error during form XSS test at {post_url}: {e}")
    return results

# Webpage se saare links extract karne ka function
def extract_links(url, base_url):
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.content, "html.parser")
        links = set()
        for a_tag in soup.find_all("a", href=True):
            href = a_tag['href']
            full_url = urljoin(base_url, href)
            if urlparse(full_url).netloc == urlparse(base_url).netloc:  # Domain ke andar hi rahna hai
                links.add(full_url)
        return links
    except requests.exceptions.RequestException as e:
        print(f"[-] Error during link extraction at {url}: {e}")
        return set()

# Website ko crawl karna aur har page par scans perform karna
def crawl_and_scan(base_url):
    to_visit = set([base_url])
    visited = set()
    results = {
        "sql_injection": [],
        "xss": [],
        "xss_in_forms": [],
        "open_redirect": [],
        "clickjacking": [],
        "csrf": []
    }

    while to_visit:
        url = to_visit.pop()
        if url in visited:
            continue
        visited.add(url)
        print(f"[+] Crawling and scanning {url}")

        # Current page par scans perform karna
        results["sql_injection"].extend(detect_sql_injection(url))
        results["xss"].extend(detect_xss(url))
        results["xss_in_forms"].extend(test_xss_in_forms(url))
        results["open_redirect"].extend(detect_open_redirect(url))
        results["clickjacking"].extend(detect_clickjacking(url))
        results["csrf"].extend(detect_csrf(url))

        # Links extract karna aur unhe pages visit karne ki list mein add karna
        links = extract_links(url, base_url)
        to_visit.update(links - visited)

        # Server overload na ho, isliye requests ke darmiyan delay add karte hain
        time.sleep(1)

    return results

# Network Tool: Port Scanning
def port_scan(domain):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    open_ports = []
    for port in common_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            if result == 0:
                open_ports.append(port)
            sock.close()
        except socket.error as e:
            pass
    return open_ports

@app.route('/')
def index():
    return render_template_string('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Web Cyber Trap</title>
        <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body {
                font-family: Arial, sans-serif;
                background-color: #f8f9fa;
                margin: 0;
                padding: 20px;
            }
            .container {
                max-width: 900px;
                margin: 0 auto;
                background-color: #fff;
                padding: 20px;
                border-radius: 8px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }
            h1, h2, h3 {
                text-align: center;
            }
            form {
                display: flex;
                flex-direction: column;
            }
            label, input, button {
                margin-bottom: 10px;
            }
            input, button {
                padding: 10px;
                font-size: 16px;
            }
            button {
                background-color: #007bff;
                color: #fff;
                border: none;
                border-radius: 4px;
                cursor: pointer;
            }
            button:hover {
                background-color: #0056b3;
            }
            #results {
                margin-top: 20px;
            }
            .result-category {
                margin-top: 20px;
            }
            .result-item {
                margin-bottom: 10px;
                padding: 10px;
                border: 1px solid #e0e0e0;
                border-radius: 4px;
            }
            .alert {
                margin-top: 20px;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Web Cyber Trap</h1>
            <h3>Students: Wasal Hassan, Umar Shah Khan</h3>
            <h3>Supervisor: Sir Naqi Abbas</h3>
            <form id="scan-form">
                <label for="url">Enter URL to Scan:</label>
                <input type="text" id="url" name="url" required>
                <button type="submit" class="btn btn-primary">Scan</button>
            </form>
            <div id="results">
                <h2>Scan Results</h2>
                <div class="result-category" id="sql-results">
                    <h3>SQL Injection</h3>
                </div>
                <div class="result-category" id="xss-results">
                    <h3>XSS</h3>
                </div>
                <div class="result-category" id="form-xss-results">
                    <h3>Form XSS</h3>
                </div>
                <div class="result-category" id="open-redirect-results">
                    <h3>Open Redirect</h3>
                </div>
                <div class="result-category" id="clickjacking-results">
                    <h3>Clickjacking</h3>
                </div>
                <div class="result-category" id="csrf-results">
                    <h3>CSRF</h3>
                </div>
                <div class="result-category" id="port-scan-results">
                    <h3>Port Scan</h3>
                </div>
            </div>
        </div>
        <script src="https://ajax.googleapis.com/ajax/libs/jquery/3.5.1/jquery.min.js"></script>
        <script src="https://maxcdn.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
        <script>
            document.getElementById('scan-form').addEventListener('submit', function(e) {
                e.preventDefault();
                const url = document.getElementById('url').value;
                const sqlResultsContainer = document.getElementById('sql-results');
                const xssResultsContainer = document.getElementById('xss-results');
                const formXssResultsContainer = document.getElementById('form-xss-results');
                const openRedirectResultsContainer = document.getElementById('open-redirect-results');
                const clickjackingResultsContainer = document.getElementById('clickjacking-results');
                const csrfResultsContainer = document.getElementById('csrf-results');
                const portScanResultsContainer = document.getElementById('port-scan-results');

                sqlResultsContainer.innerHTML = '<h3>SQL Injection</h3>';
                xssResultsContainer.innerHTML = '<h3>XSS</h3>';
                formXssResultsContainer.innerHTML = '<h3>Form XSS</h3>';
                openRedirectResultsContainer.innerHTML = '<h3>Open Redirect</h3>';
                clickjackingResultsContainer.innerHTML = '<h3>Clickjacking</h3>';
                csrfResultsContainer.innerHTML = '<h3>CSRF</h3>';
                portScanResultsContainer.innerHTML = '<h3>Port Scan</h3>';

                fetch('/scan', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({ url: url })
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        sqlResultsContainer.innerHTML += `<div class="alert alert-danger">${data.error}</div>`;
                        return;
                    }
                    const sqlResults = data.sql_injection;
                    const xssResults = data.xss;
                    const formXssResults = data.xss_in_forms;
                    const openRedirectResults = data.open_redirect;
                    const clickjackingResults = data.clickjacking;
                    const csrfResults = data.csrf;

                    if (sqlResults.length > 0) {
                        sqlResults.forEach(result => {
                            const div = document.createElement('div');
                            div.classList.add('result-item');
                            div.textContent = result;
                            sqlResultsContainer.appendChild(div);
                        });
                    } else {
                        const div = document.createElement('div');
                        div.classList.add('result-item');
                        div.textContent = '[+] No SQL Injection vulnerability detected.';
                        sqlResultsContainer.appendChild(div);
                    }

                    if (xssResults.length > 0) {
                        xssResults.forEach(result => {
                            const div = document.createElement('div');
                            div.classList.add('result-item');
                            div.textContent = result;
                            xssResultsContainer.appendChild(div);
                        });
                    } else {
                        const div = document.createElement('div');
                        div.classList.add('result-item');
                        div.textContent = '[+] No XSS vulnerability detected.';
                        xssResultsContainer.appendChild(div);
                    }

                    if (formXssResults.length > 0) {
                        formXssResults.forEach(result => {
                            const div = document.createElement('div');
                            div.classList.add('result-item');
                            div.textContent = result;
                            formXssResultsContainer.appendChild(div);
                        });
                    } else {
                        const div = document.createElement('div');
                        div.classList.add('result-item');
                        div.textContent = '[+] No XSS vulnerability detected in forms.';
                        formXssResultsContainer.appendChild(div);
                    }

                    if (openRedirectResults.length > 0) {
                        openRedirectResults.forEach(result => {
                            const div = document.createElement('div');
                            div.classList.add('result-item');
                            div.textContent = result;
                            openRedirectResultsContainer.appendChild(div);
                        });
                    } else {
                        const div = document.createElement('div');
                        div.classList.add('result-item');
                        div.textContent = '[+] No Open Redirect vulnerability detected.';
                        openRedirectResultsContainer.appendChild(div);
                    }

                    if (clickjackingResults.length > 0) {
                        clickjackingResults.forEach(result => {
                            const div = document.createElement('div');
                            div.classList.add('result-item');
                            div.textContent = result;
                            clickjackingResultsContainer.appendChild(div);
                        });
                    } else {
                        const div = document.createElement('div');
                        div.classList.add('result-item');
                        div.textContent = '[+] No Clickjacking vulnerability detected.';
                        clickjackingResultsContainer.appendChild(div);
                    }

                    if (csrfResults.length > 0) {
                        csrfResults.forEach(result => {
                            const div = document.createElement('div');
                            div.classList.add('result-item');
                            div.textContent = result;
                            csrfResultsContainer.appendChild(div);
                        });
                    } else {
                        const div = document.createElement('div');
                        div.classList.add('result-item');
                        div.textContent = '[+] No CSRF vulnerability detected.';
                        csrfResultsContainer.appendChild(div);
                    }

                    // Network Tools Results
                    const domain = new URL(url).hostname;
                    fetch('/network_tools', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ domain: domain })
                    })
                    .then(response => response.json())
                    .then(networkData => {
                        const openPorts = networkData.open_ports;

                        if (openPorts.length > 0) {
                            openPorts.forEach(port => {
                                const div = document.createElement('div');
                                div.classList.add('result-item');
                                div.textContent = `Open port: ${port}`;
                                portScanResultsContainer.appendChild(div);
                            });
                        } else {
                            const div = document.createElement('div');
                            div.classList.add('result-item');
                            div.textContent = '[+] No open ports detected.';
                            portScanResultsContainer.appendChild(div);
                        }
                    })
                    .catch(error => console.error('Error:', error));
                })
                .catch(error => console.error('Error:', error));
            });
        </script>
    </body>
    </html>
    ''')

# Scan request handle karne ka route
@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = validate_url(data['url'])
    if not url:
        return jsonify({"error": "Invalid or unreachable URL"}), 400
    results = crawl_and_scan(url)
    return jsonify(results)

# Network tools request handle karne ka route
@app.route('/network_tools', methods=['POST'])
def network_tools():
    data = request.get_json()
    domain = data['domain']
    open_ports = port_scan(domain)
    return jsonify({"open_ports": open_ports})

if __name__ == "__main__":
    app.run(debug=True)
