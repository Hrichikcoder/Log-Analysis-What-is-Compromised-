import pandas as pd
from collections import Counter, defaultdict
import json
import os

# Set paths relative to your D:\log analysis folder
DATA_DIR = "data"
OUTPUT_JSON = "compromise_summary.json"

def run_analysis():
    print("Starting Log Analysis...")
    compromised = {}

    # 1. ANALYZE USB EVENTS
    print("Analyzing USB Logs...")
    usb = pd.read_csv(f"{DATA_DIR}/usb_events.csv")
    for _, r in usb.iterrows():
        # Hunting for the known suspicious USB signature
        if 'abcd:1234' in str(r['message']):
            ep = r['endpoint_id']
            compromised.setdefault(ep, []).append(f"USB: Suspicious mass storage 'abcd:1234' inserted at {r['event_time']}")

    # 2. ANALYZE ENDPOINT SECURITY
    print("Analyzing Endpoint Security Logs...")
    sec = pd.read_csv(f"{DATA_DIR}/endpoint_security.csv")
    
    # Find quarantined files marked explicitly as 'Malicious'
    malicious_q = sec[sec['message'].str.contains('FileType: Malicious', na=False)].copy()
    malicious_q['file_name'] = malicious_q['message'].str.extract(r'File: (.+?) \|', expand=False)
    malicious_q['file_sha'] = malicious_q['message'].str.extract(r'SHA256: ([a-f0-9]+)', expand=False)
    
    # Deduplicate so we don't report the same file 100 times for one endpoint
    malicious_q_dedup = malicious_q.drop_duplicates(subset=['endpoint_id','file_sha'])
    
    for ep in malicious_q_dedup['endpoint_id'].unique():
        files = malicious_q_dedup[malicious_q_dedup['endpoint_id']==ep]['file_name'].tolist()
        compromised.setdefault(ep, []).append(f"AV: Malicious file(s) quarantined: {', '.join(set(files))}")

    # 3. ANALYZE WEB ACTIVITY (Processed in chunks to save memory)
    print("Analyzing Web Activity (This may take a moment)...")
    example_hits = defaultdict(list)
    
    # Read the massive CSV in chunks of 500k rows
    for chunk in pd.read_csv(f"{DATA_DIR}/web_activity.csv", chunksize=500_000):
        # Look for simulated C2 domains ending in .example
        example = chunk[chunk['message'].str.endswith('.example', na=False)]
        for _, r in example.iterrows():
            example_hits[r['endpoint_id']].append((r['event_time'], r['message']))

    for ep, hits in example_hits.items():
        # Grab up to 3 unique domains they connected to
        domains = list(set([h[1] for h in hits]))
        compromised.setdefault(ep, []).append(f"C2 Beacon: Connected to suspicious domains {domains[:3]}")

    # 4. EVASION DETECTION
    # If an endpoint is in the USB logs but missing from Security logs, the AV was disabled.
    sec_eps = set(sec['endpoint_id'].unique())
    usb_eps = set(usb['endpoint_id'].unique())
    missing_from_sec = usb_eps - sec_eps
    for ep in missing_from_sec:
        compromised.setdefault(ep, []).append("EVASION: Endpoint AV/Logging agent was forcibly disabled.")

    # 5. SAVE RESULTS
    with open(OUTPUT_JSON, 'w', encoding='utf-8') as f:
        json.dump(compromised, f, indent=2, ensure_ascii=False)
    
    print(f"\nAnalysis complete! Flagged {len(compromised)} endpoints.")
    print(f"Raw data saved to {OUTPUT_JSON}")

if __name__ == "__main__":
    run_analysis()