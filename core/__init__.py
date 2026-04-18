import os
import re
import json

class Scanner:
    def __init__(self, db_path='database/signatures.json'):
        with open(db_path, 'r') as f:
            self.signatures = json.load(f)['signatures']

    def scan_directory(self, repo_path):
        findings = []
        # Walk through the directory
        for root, _, files in os.walk(repo_path):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                        
                        # Check each signature
                        for sig in self.signatures:
                            if re.search(sig['pattern'], content):
                                findings.append({
                                    "file": file_path,
                                    "signature": sig['name'],
                                    "provider": sig['provider'],
                                    "severity": sig['severity'],
                                    "snippet": "HIDDEN_IN_LOGS" # Don't log actual key
                                })
                except Exception as e:
                    print(f"Error reading {file_path}: {e}")
        return findings