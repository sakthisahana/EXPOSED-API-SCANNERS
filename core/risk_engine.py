class RiskEngine:
    def __init__(self):
        # Risk Weights
        self.weights = {
            "CRITICAL": 40,
            "HIGH": 30,
            "MEDIUM": 20,
            "LOW": 10
        }
        
        # Define Frameworks and their standard requirements
        self.framework_definitions = {
            "ISO_27001": {
                "name": "ISO/IEC 27001",
                "control_id": "A.9.4.1",
                "control_name": "Information Access Restriction",
                "desc": "Access to applications and system functions shall be restricted in accordance with the access control policy.",
                "fix": "Remove hardcoded credentials and implement a centralized Secrets Management system (e.g., AWS Secrets Manager)."
            },
            "OWASP": {
                "name": "OWASP Top 10",
                "control_id": "A07:2021",
                "control_name": "Identification and Authentication Failures",
                "desc": "Confirmation of user identity, authentication, and session management is critical to protect against authentication-related attacks.",
                "fix": "Use environment variables for API keys and ensure they are never committed to version control."
            },
            "NIST_CSF": {
                "name": "NIST Cybersecurity Framework",
                "control_id": "PR.AC-1",
                "control_name": "Access Control",
                "desc": "Identities and credentials are managed for authorized devices and users.",
                "fix": "Rotate the exposed credential immediately and update .gitignore to prevent future leaks."
            },
            "PCI_DSS": {
                "name": "PCI DSS v4.0",
                "control_id": "Requirement 3",
                "control_name": "Protect Stored Account Data",
                "desc": "Protection of cardholder data is a critical requirement for any system handling payments.",
                "fix": "Immediately rotate keys and ensure no plaintext payment-related secrets remain in the codebase."
            },
            "SOC2": {
                "name": "SOC 2 Type II",
                "control_id": "CC6.1",
                "control_name": "Logical Access Security",
                "desc": "The entity restricts logical access to confidential information to authorized users.",
                "fix": "Audit access logs for the exposed key to ensure no unauthorized data access occurred."
            }
        }

    def calculate_risk(self, finding):
        # Your existing risk logic
        base_score = self.weights.get(finding.get('severity', 'LOW'), 10)
        total_score = min(base_score + 40, 100) # Simplified for demo
        
        return {
            "score": total_score,
            "level": "CRITICAL" if total_score > 80 else "HIGH" if total_score > 50 else "MEDIUM"
        }

    def get_compliance_results(self, findings):
        """
        Processes findings and maps them to the 5 major frameworks.
        """
        results = []
        
        # If there are ANY findings, all frameworks are marked as NON-COMPLIANT
        status = "NON-COMPLIANT" if len(findings) > 0 else "COMPLIANT"
        
        for fw_id, info in self.framework_definitions.items():
            violated_controls = []
            
            if len(findings) > 0:
                # In a real app, you'd map specific findings to specific controls.
                # For this project, a finding violates the core credential rule of every framework.
                violated_controls.append({
                    "control_id": info["control_id"],
                    "control_name": info["control_name"],
                    "description": info["desc"],
                    "violation": f"Found {len(findings)} exposed secrets in the repository, violating plaintext storage policies.",
                    "remediation": info["fix"]
                })

            results.append({
                "framework": fw_id,
                "framework_name": info["name"],
                "compliance_status": status,
                "total_violations": len(violated_controls),
                "violated_controls": violated_controls,
                "severity": "HIGH" if status == "NON-COMPLIANT" else "LOW"
            })
            
        return results