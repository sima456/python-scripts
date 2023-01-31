import requests
import argparse
import json

VT_API_KEY = 'Your API Key here'
VT_BASE_URL = 'https://www.virustotal.com/api/v3/'

def search_hash(hash_value):
    url = VT_BASE_URL + 'files/' + hash_value
    headers = {'x-apikey': VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def search_ip(ip_address):
    url = VT_BASE_URL + 'ip_addresses/' + ip_address
    headers = {'x-apikey': VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def search_domain(domain):
    url = VT_BASE_URL + 'domains/' + domain
    headers = {'x-apikey': VT_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        return None

def search_file(file_path):
    with open(file_path, 'rb') as f:
        file_content = f.read()
    url = VT_BASE_URL + 'files'
    headers = {'x-apikey': VT_API_KEY}
    response = requests.post(url, headers=headers, files={'file': file_content})
    if response.status_code == 200:
        return response.json()
    else:
        return None

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='VirusTotal search')
    parser.add_argument('search_type', choices=['hash', 'ip', 'domain', 'file'], help='type of search')
    parser.add_argument('search_value', help='value to search')
    args = parser.parse_args()

    if args.search_type == 'hash':
        result = search_hash(args.search_value)
    elif args.search_type == 'ip':
        result = search_ip(args.search_value)
    elif args.search_type == 'domain':
        result = search_domain(args.search_value)
    elif args.search_type == 'file':
        result = search_file(args.search_value)

    if result:
        print(json.dumps(result, indent=4))
    else:
        print('No result found')
