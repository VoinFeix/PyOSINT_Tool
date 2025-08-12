import os
import threading
from dotenv import load_dotenv
import shodan
import json
import requests
import subprocess
from tkinter import messagebox
import whois
import dns.resolver
import hashlib

load_dotenv()
API_KEY = os.getenv("SHODAN_API_KEY")
api = shodan.Shodan(API_KEY)

CACHE_DIR = "cache"

os.makedirs(CACHE_DIR, exist_ok=True)

def _cache_path(target):
    return os.path.join(CACHE_DIR, f"{target}.json")

def load_cache(target):
    path = _cache_path(target)
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)

    return None

def save_cache(target, data):
    with open(_cache_path(target), "w") as f:
        json.dump(data, f, indent=2)

def format_shodan_data(data):
    if not data:
        return "\n❌ No data found for the given IP.\n"

    output = []
    output.append("\n🔍 ===== Shodan Host Information =====\n")
    
    output.append(f"🌐 IP Address       : {data.get('ip_str', 'N/A')}")
    output.append(f"🏢 Organization     : {data.get('org', 'N/A')}")
    output.append(f"📡 ISP              : {data.get('isp', 'N/A')}")
    output.append(f"🔢 ASN              : {data.get('asn', 'N/A')}")
    output.append(f"💻 Operating System : {data.get('os', 'N/A')}")
    output.append(f"🕒 Last Update      : {data.get('last_update', 'N/A')}")
    output.append(f"📍 Country          : {data.get('country_name', 'N/A')}")
    output.append(f"🏙️ City             : {data.get('city', 'N/A')}")
    output.append(f"🗺️ Latitude         : {data.get('latitude', 'N/A')}")
    output.append(f"🗺️ Longitude        : {data.get('longitude', 'N/A')}")

    if "tags" in data and data["tags"]:
        output.append(f"🏷️ Tags             : {', '.join(data['tags'])}")

    if "hostnames" in data and data["hostnames"]:
        output.append(f"🖥️ Hostnames        : {', '.join(data['hostnames'])}")

    if "domains" in data and data["domains"]:
        output.append(f"🌍 Domains          : {', '.join(data['domains'])}")

    # Open Ports
    output.append("\n🚪 ===== Open Ports & Services =====\n")
    for service in data.get("data", []):
        port = service.get("port", "N/A")
        transport = service.get("transport", "N/A")
        product = service.get("product", "N/A")
        version = service.get("version", "N/A")
        banner = service.get("data", "").strip()

        output.append(f"\n🔹 Port {port}/{transport} → {product} {version}")
        if "http" in service:
            http_info = service["http"]
            output.append(f"    📄 HTTP Title : {http_info.get('title', 'N/A')}")
            output.append(f"    🖥️ Server     : {http_info.get('server', 'N/A')}")
        if banner:
            if len(banner) > 300:
                banner = banner[:300] + "... [truncated]"
            output.append(f"    📜 Banner:\n{banner}")

    # Vulnerabilities
    vulns = data.get("vulns", {})
    if vulns:
        output.append("\n⚠️ ===== Vulnerabilities =====\n")
        for vuln_id, vuln_info in vulns.items():
            output.append(f"- {vuln_id}")
            if isinstance(vuln_info, dict):
                summary = vuln_info.get("summary", "No summary available.")
                output.append(f"  📝 Summary: {summary}")

    return "\n".join(output)



def shodan_lookup(target, callback):
    def run_lookup():
        cached = load_cache(target)
        if cached:
            callback(format_shodan_data(cached))
            return

        try:
            if target.replace(".", "").isdigit():
                data = api.host(target)
            else:
                data = api.search(target)

            save_cache(target, data)
            callback(format_shodan_data(data))

        except shodan.APIError as e:
            callback(f"Error: {e}")

    threading.Thread(target=run_lookup, daemon=True).start()

def email_lookup(target, callback):
    def run_lookup():
        result_lines = []
        result_lines.append("📧 ===== Email Lookup =====\n")
        try:
            if "@" in target:
                domain = target.split("@")[1]
                result_lines.append(f"🌍 Email Domain : {domain}")
            else:
                result_lines.append("❌ Invalid email format.")

            gravatar_hash = hashlib.md5(target.lower().encode()).hexdigest()
            gravatar_url = f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404"
            result_lines.append(f"🖼️ Gravatar URL : {gravatar_url}")

            result_lines.append(f"🔍 OSINT Tip    : Search → \"{target}\" site:pastebin.com")

        except Exception as e:
            result_lines.append(f"⚠️ Error: {e}")

        callback("\n".join(result_lines))

    threading.Thread(target=run_lookup, daemon=True).start()

def domain_lookup(target, callback):
    def run_lookup():
        result_lines = []
        result_lines.append("\n🌐 ===== Domain Lookup =====\n")
        try:
            w = whois.query(target)
            if w:
                result_lines.append(f"📛 Name        : {w.name}")
                result_lines.append(f"🏢 Registrar   : {w.registrar}")
                result_lines.append(f"📅 Created     : {w.creation_date}")
                result_lines.append(f"⏳ Expires     : {w.expiration_date}")
            else:
                result_lines.append("❌ WHOIS data not found.")

            result_lines.append("\n📡 === DNS Records ===")
            for record_type in ["A", "AAAA", "MX", "NS", "TXT"]:
                try:
                    answers = dns.resolver.resolve(target, record_type)
                    for rdata in answers:
                        result_lines.append(f"  {record_type} → {rdata.to_text()}")
                except Exception:
                    pass

        except Exception as e:
            result_lines.append(f"⚠️ Error: {e}")

        callback("\n".join(result_lines))

    threading.Thread(target=run_lookup, daemon=True).start()

def username_lookup(target, callback):
    def run_lookup():
        result_text = "\n👤 ===== Username Lookup =====\n"
        try:
            if subprocess.call(['which', 'sherlock']) != 0 and not os.path.exists(os.path.expanduser('~/.local/bin/sherlock')):
                subprocess.run(['pip3', 'install', '--user', 'sherlock-project'])

            try:
                result = subprocess.run(["sherlock", target], capture_output=True, text=True)
            except FileNotFoundError:
                result = subprocess.run([os.path.expanduser('~/.local/bin/sherlock'), target], capture_output=True, text=True)

            result_text += result.stdout.strip() or "❌ No results found."

        except Exception as e:
            result_text += f"⚠️ Error running Sherlock: {e}"
    
        callback(result_text)

    threading.Thread(target=run_lookup, daemon=True).start()
