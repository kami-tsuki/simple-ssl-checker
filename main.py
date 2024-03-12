import ssl
import socket
from datetime import datetime
from rich import print as rprint
from rich.box import ROUNDED
from rich.panel import Panel
from rich.text import Text
import os
import json
import xml.etree.ElementTree as et
import yaml
from urllib.parse import urlparse
import time


def check_ssl_certificate(host, port=443) -> bool:
    context = ssl.create_default_context()
    conn = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=host)
    conn.settimeout(3.0)
    conn.connect((host, port))
    ssl_info = conn.getpeercert()

    # Get dates
    not_before = datetime.strptime(ssl_info['notBefore'], r'%b %d %H:%M:%S %Y %Z')
    not_after = datetime.strptime(ssl_info['notAfter'], r'%b %d %H:%M:%S %Y %Z')
    now = datetime.now()

    # Calculate remaining days
    remaining = (not_after - now).days

    # Prepare information
    info = f"Domain: {ssl_info['subject'][0][0][1]}\n"
    info += f"Host: {host} Port: {port}\n"
    info += f"Protocol: {ssl_info['version']}\n"
    info += f"Organization: {ssl_info['issuer'][1][0][1]}\n"
    info += f"Certificate: {ssl_info['issuer'][2][0][1]}\n"
    info += f"Valid from: {not_before}\n"
    info += f"Valid to: {not_after}\n"

    # Check validity and print color
    if remaining < 0:
        info += "Certificate is not valid."
        rprint(Panel(Text(info, style="red"), box=ROUNDED, expand=False))
        return False
    elif remaining < 7:
        info += "Certificate is valid for less than a week."
        rprint(Panel(Text(info, style="orange1"), box=ROUNDED, expand=False))
        return True
    elif remaining < 30:
        info += "Certificate is valid for less than a month."
        rprint(Panel(Text(info, style="yellow"), box=ROUNDED, expand=False))
        return True
    else:
        info += "Certificate is valid for over a month."
        rprint(Panel(Text(info, style="green"), box=ROUNDED, expand=False))
        return True


def read_hosts_from_file(file_path):
    r_hosts = []
    if file_path.endswith('.json'):
        with open(file_path, 'r') as f:
            data = json.load(f)
            r_hosts = data.get('hosts', [])
    elif file_path.endswith('.xml'):
        tree = et.parse(file_path)
        root = tree.getroot()
        r_hosts = [host.text for host in root.findall('host')]
    elif file_path.endswith('.yml') or file_path.endswith('.yaml'):
        with open(file_path, 'r') as f:
            data = yaml.safe_load(f)
            r_hosts = data.get('hosts', [])
    return r_hosts


def extract_host_from_url(url):
    parsed_uri = urlparse(url)
    return parsed_uri.netloc


def save_hosts_to_json(hosts, file_path):
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, 'w') as f:
        json.dump({'hosts': hosts}, f)


def main():
    hosts = []
    input_type = input("Enter the input type ([t]ext/[f]ile): ")
    if input_type.lower()[0] == 't':
        hosts = input("Enter the hosts (comma-separated): ")
        hosts = hosts.replace(" ", "").split(",")
        timestamp = int(time.time())
        json_file_path = f"saves/hosts/{timestamp}.json"
        save_hosts_to_json(hosts, json_file_path)
    elif input_type.lower()[0] == 'f':
        file_path = input("Enter the file path: ")
        hosts = read_hosts_from_file(file_path)
        save_to_json = input("Do you want to save the hosts to a JSON file? ([y]es/[n]o): ")
        if save_to_json.lower()[0] == 'y':
            json_file_path = input("Enter the path to save the JSON file: ")
            save_hosts_to_json(hosts, json_file_path)
    else:
        print("Invalid input type. Please enter either 'text' or 'file'.")
        main()

    if not hosts or len(hosts) == 0:
        print("No hosts found.")
        return

    for host in hosts:
        host = extract_host_from_url(host)
        try:
            check_ssl_certificate(host)
        except Exception as e:
            print(f"An error occurred while checking the SSL certificate for {host}: {e}")


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting...")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print("Program finished.")
