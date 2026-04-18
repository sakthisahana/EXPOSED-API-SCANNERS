from flask import Flask, jsonify, request
from core.scanner import Scanner
from core.risk_engine import RiskEngine
from core.mitigator import Mitigator
import json
import datetime
import os
import shutil       # To delete folders
import stat         # To handle Windows permissions
import subprocess   # To run 'git clone'

app = Flask(__name__)

# Initialize Core Modules
scanner = Scanner()
risk_engine = RiskEngine()
mitigator = Mitigator()

# Database Paths
DB_HISTORY = 'database/scan_history.json'
DB_POLICIES = 'database/policies.json'
TEMP_REPO_PATH = './temp_cloned_repo'

# --- HELPER FUNCTIONS ---

def save_history(new_results):
    history = []
    if os.path.exists(DB_HISTORY):
        try:
            with open(DB_HISTORY, 'r') as f:
                content = f.read().strip()
                if content:
                    history = json.loads(content)
        except (json.JSONDecodeError, Exception):
            history = []
    history.extend(new_results)
    with open(DB_HISTORY, 'w') as f:
        json.dump(history, f, indent=4)

def remove_readonly(func, path, excinfo):
    """
    Helper to force delete read-only files on Windows.
    """
    os.chmod(path, stat.S_IWRITE)
    func(path)

def clone_repository(url):
    """
    Clones a remote GitHub URL to a temporary local folder.
    """
    # 1. Cleanup: Delete previous temp repo if it exists
    if os.path.exists(TEMP_REPO_PATH):
        try:
            # The 'onerror' handler fixes the [WinError 5] Access Denied
            shutil.rmtree(TEMP_REPO_PATH, onerror=remove_readonly)
        except Exception as e:
            print(f"[!] Error cleaning up old repo: {e}")
            return False

    # 2. Clone: Run the git command
    print(f"[*] Cloning {url}...")
    try:
        subprocess.check_call(["git", "clone", url, TEMP_REPO_PATH])
        return True
    except subprocess.CalledProcessError as e:
        print(f"[!] Git clone failed: {e}")
        return False
    except FileNotFoundError:
        print("[!] Error: 'git' command not found. Is Git installed?")
        return False

# --- API ROUTES ---

@app.route('/')
def home():
    return jsonify({"status": "Risk Scanner API Running"})

@app.route('/scan', methods=['POST'])
def run_scan():
    user_input = request.json.get('path', './vulnerable_repo')
    target_path = user_input
    
    # --- LOGIC SWITCH: URL vs LOCAL ---
    if user_input.startswith("http"):
        # It is a URL -> Clone it first
        success = clone_repository(user_input)
        if not success:
            return jsonify({"message": "Failed to clone repository. Check URL or Internet."}), 400
        target_path = TEMP_REPO_PATH
    else:
        # It is a local folder -> Check if it exists
        if not os.path.exists(target_path):
             return jsonify({"message": f"Local folder '{target_path}' not found."}), 404

    # 1. Scan the target (either the cloned repo or local folder)
    raw_findings = scanner.scan_directory(target_path)
    
    # 2. Process Risks & Policies
    processed_results = []
    try:
        with open(DB_POLICIES, 'r') as f:
            policy_map = json.load(f)['mappings']
    except FileNotFoundError:
        policy_map = {}

    for finding in raw_findings:
        risk_data = risk_engine.calculate_risk(finding)
        policies = policy_map.get(finding['severity'], [])
        
        result = {
            "timestamp": str(datetime.datetime.now()),
            "finding": finding,
            "risk": risk_data,
            "policies_violated": policies,
            "mitigated": False,
            "source_repo": user_input # Track where this came from
        }
        processed_results.append(result)

    save_history(processed_results)
    
    return jsonify({
        "message": "Scan Complete", 
        "findings_count": len(processed_results),
        "results": processed_results
    })

@app.route('/mitigate', methods=['POST'])
def mitigate_risk():
    data = request.json
    finding = data.get('finding')
    
    # Execute Mitigation
    result = mitigator.mitigate_finding(finding)
    
    return jsonify(result)

@app.route('/history', methods=['GET'])
def get_history():
    history = []
    if os.path.exists(DB_HISTORY):
        try:
            with open(DB_HISTORY, 'r') as f:
                content = f.read().strip()
                if content:
                    history = json.loads(content)
        except json.JSONDecodeError:
            history = []
    return jsonify(history)

if __name__ == '__main__':
    app.run(debug=True, port=5000)