import requests
import csv
import time
import logging

# Constants
VIRUSTOTAL_API_KEY = ""
HASH_FILE = '../data/static/unpacked_hashes.md5'
OUTPUT_FILE = '../data/static/metadata_collection.csv'
LOG_FILE = '../logs/metadata_collection.log'
selectAPI = 0

# Auto changing the api
def change_API(nextAPI):
    api_list = []
    return api_list[nextAPI]

# Setup logging
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format='%(asctime)s - %(message)s')

# Function to fetch metadata from VirusTotal
def fetch_metadata(hash_value):
    global selectAPI
    global VIRUSTOTAL_API_KEY
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        logging.warning(f"Failed to fetch metadata for hash: {hash_value}, Status Code: {response.status_code}")
        print(f"failed hash: {hash_value} -> API: {VIRUSTOTAL_API_KEY}")
        selectAPI = selectAPI+1
        #Changing the API
        if (selectAPI<11):
            VIRUSTOTAL_API_KEY = change_API(selectAPI)
        else:
            selectAPI = 0
            VIRUSTOTAL_API_KEY = change_API(selectAPI)

        return None

# Main function to process hashes
def collect_metadata():
    global VIRUSTOTAL_API_KEY
    global selectAPI
    with open(HASH_FILE, 'r') as f:
        hashes = [line.strip() for line in f]

    #API selector
    VIRUSTOTAL_API_KEY = change_API(selectAPI)

    # Prepare output CSV
    with open(OUTPUT_FILE, 'w', newline='') as csvfile:
        fieldnames = ['md5', 'first_submission_date', 'last_analysis_stats', 'malicious_votes']
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()

        # Process each hash
        for md5 in hashes:
            metadata = fetch_metadata(md5)
            if metadata:
                try:
                    # Extract relevant fields
                    writer.writerow({
                        'md5': md5,
                        'first_submission_date': metadata['data']['attributes'].get('first_submission_date', 'N/A'),
                        'last_analysis_stats': metadata['data']['attributes'].get('last_analysis_stats', {}),
                        'malicious_votes': metadata['data']['attributes'].get('last_analysis_stats', {}).get('malicious', 0),
                    })
                    logging.info(f"Successfully collected metadata for hash: {md5}")
                except Exception as e:
                    logging.error(f"Error processing metadata for hash: {md5}, Error: {e}")

            time.sleep(3)  # Respect API rate limits

if __name__ == "__main__":
    collect_metadata()
