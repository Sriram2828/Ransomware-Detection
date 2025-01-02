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
    api_list = ["bb51579a8b06c9c18bdc2c69ee66bd6cd6e79f1a7e8426ac448b354a668a19e7", "e2ada0bb6ba29cce58d09981fbca04d7e878c1364a4feabb4da45cf3fbfbe121",
                "a46a3915e14d6904c00d63bd3bd01011ff7b28f950f1847f38c521b4f57c4b66", "ea190a14914e70d939317fddaf44ca182b873656978acda30439262146a93403",
                "41bd1f01482a86f7f09142dcabfd748e544eaf1db9af0fdaf11ce362620994e4", "6c409f0c016410b8865dc6dbfb769feecc8eafb2181d7d022d87e39a6f665da4",
                "1a868d4a0c4ea88cf66db21271410706dedfca8f2b1bf54f536fdd9f9c3cc766", "b223a9c6863f112aa090f1dac17fd23499d1776b3b8816db97dd5753bdd05112",
                "80a7e01a8e6e671323581d4f0836da3169dc82d47c5a549bc20f548d49c154f0", "0e316539da3b7ed609d3f6bd072f219015646fe4b9e1ef9e68fa5c81adba0393",
                "6ce6e8174eeecdfbc8b0f0e4263c53fb01366bf8aacc693550a27a2ccb9ed4c0", "ee3b64c982d63995ffae2665238b3d70c3f1ee0a59297afacda309652391b4eb",
                "c7e0f3cf81dc8a07a82f05d7c771302be468d5ff899823452040709f7b483a02", "78fb1f78a9d8feb1fbdfcbb3c765a6b02e254e24c9c95a459276254f37fd527e",
                "a9baccb59af6496b74e22924e4c9ab352d7e2cadb499e3dde710a38d5dac807f", "184a31911fdbc56ed241fc6b65f316714119fa1caa76ec1f6a7e4fb536343221",
                "8b99220f2c47c91511244df6a08a0106b1b47daf16c3b104278fbe480a34dcb2", "bdb3dcf0e4cad46c2c34b24178d0e58a13d32fa014ece6bc520c1f6ae1143b5b"]
                
    
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

            time.sleep(5)  # Respect API rate limits

if __name__ == "__main__":
    collect_metadata()
