import os
import requests
from dotenv import load_dotenv

# Load API key from .env file
load_dotenv()
API_KEY = os.getenv("VT_API_KEY")

class VirusTotalAPI:
    BASE_URL = "https://www.virustotal.com/api/v3/"

    def __init__(self, api_key):
        if not api_key:
            raise ValueError("Missing VirusTotal API key. Make sure it's set in your .env file.")
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}

    def scan_hash(self, file_hash):
        url = f"{self.BASE_URL}files/{file_hash}"
        response = requests.get(url, headers=self.headers)
        return response.json() if response.status_code == 200 else {"error": "Failed to retrieve data"}

if __name__ == "__main__":
    vt = VirusTotalAPI(API_KEY)
    
    # Example hash for testing
    sample_hash = input("Enter file hash to scan: ").strip()
    result = vt.scan_hash(sample_hash)
    print(result)
