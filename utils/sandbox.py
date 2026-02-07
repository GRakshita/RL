# utils/sandbox.py
import requests
import time
import os
from config import LITTERBOX_API

def analyze_payload(file_path):
    """Upload to Litterbox and get detection score"""
    
    # 1. Upload
    with open(file_path, "rb") as f:
        files = {'file': f}
        resp = requests.post(f"{LITTERBOX_API}/upload", files=files)
    
    if resp.status_code != 200:
        return 100  # Fail = 100% detection
    
    file_hash = resp.json()['file_info']['md5']
    
    # 2. Trigger analysis
    requests.post(f"{LITTERBOX_API}/analyze/dynamic/{file_hash}")
    requests.post(f"{LITTERBOX_API}/analyze/static/{file_hash}")
    
    # 3. Wait for results
    time.sleep(5)
    
    for _ in range(10):
        dyn = requests.get(f"{LITTERBOX_API}/api/results/{file_hash}/dynamic")
        stat = requests.get(f"{LITTERBOX_API}/api/results/{file_hash}/static")
        
        if dyn.status_code == 200 and stat.status_code == 200:
            results = requests.get(f"{LITTERBOX_API}/api/results/{file_hash}/info").json()

            detection_score = results["risk_assessment"]["score"]
            return detection_score
        
        time.sleep(3)
    
    return 100  # Timeout = 100% detection

