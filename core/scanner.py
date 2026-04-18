import os
import re
import json

class Scanner:
    def __init__(self, db_path='database/signatures.json'):
        """
        Initialize the scanner by loading regex signatures from the database.
        """
        self.signatures = []
        try:
            with open(db_path, 'r') as f:
                data = json.load(f)
                self.signatures = data.get('signatures', [])
            print(f"[*] Scanner loaded {len(self.signatures)} signatures.")
        except FileNotFoundError:
            print(f"[!] Error: Signature database not found at {db_path}")
        except json.JSONDecodeError:
            print(f"[!] Error: Invalid JSON in signature database.")

    def scan_directory(self, repo_path):
        """
        Recursively scans the target directory for secrets matching the signatures.
        Returns a list of finding dictionaries.
        """
        findings = []
        
        # Walk through the directory structure
        for root, dirs, files in os.walk(repo_path):
            # Optimization: Skip .git directories to save time
            if '.git' in dirs:
                dirs.remove('.git')
                
            for file_name in files:
                file_path = os.path.join(root, file_name)
                
                # Skip checking the scanner itself or the database files
                if "scan_history.json" in file_name or "signatures.json" in file_name:
                    continue

                try:
                    self._scan_file(file_path, findings)
                except Exception as e:
                    # Fail silently on unreadable files (images, binaries)
                    continue
                    
        return findings

    def _scan_file(self, file_path, findings_list):
        """
        Helper function to read a single file and match patterns.
        """
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()

        for line_num, line in enumerate(lines, 1):
            for sig in self.signatures:
                # Check if the regex pattern exists in the line
                if re.search(sig['pattern'], line):
                    
                    # SECURITY FEATURE: Redact the actual secret in logs
                    # We only show the first few chars to prove valid detection
                    redacted_snippet = line.strip()[:20] + "..." 

                    findings_list.append({
                        "file": file_path,
                        "line": line_num,
                        "signature_id": sig['id'],
                        "signature_name": sig['name'],
                        "provider": sig['provider'],
                        "severity": sig['severity'],
                        "snippet": redacted_snippet,
                        "full_path": os.path.abspath(file_path)
                    })