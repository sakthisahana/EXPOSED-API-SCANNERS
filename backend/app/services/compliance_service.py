from typing import List, Dict


class ComplianceService:
    """
    Milestone 4: Compliance & Policy Mapping
    """
    
    def __init__(self):
        self.frameworks = {
            "ISO_27001": {
                "name": "ISO/IEC 27001:2013",
                "controls": {
                    "A.9.4.1": {
                        "name": "Information access restriction",
                        "description": "Access to information and application system functions shall be restricted in accordance with the access control policy.",
                        "category": "Access Control"
                    },
                    "A.9.4.2": {
                        "name": "Secure log-on procedures",
                        "description": "Where required by the access control policy, access to systems and applications shall be controlled by a secure log-on procedure.",
                        "category": "Access Control"
                    },
                    "A.10.1.1": {
                        "name": "Policy on the use of cryptographic controls",
                        "description": "A policy on the use of cryptographic controls for protection of information shall be developed and implemented.",
                        "category": "Cryptography"
                    },
                    "A.10.1.2": {
                        "name": "Key management",
                        "description": "A policy on the use, protection and lifetime of cryptographic keys shall be developed and implemented through their whole lifecycle.",
                        "category": "Cryptography"
                    }
                }
            },
            "NIST_CSF": {
                "name": "NIST Cybersecurity Framework",
                "controls": {
                    "PR.AC-1": {
                        "name": "Identity and Credential Management",
                        "description": "Identities and credentials are issued, managed, verified, revoked, and audited for authorized devices, users and processes",
                        "category": "Protect"
                    },
                    "PR.AC-4": {
                        "name": "Access permissions and authorizations",
                        "description": "Access permissions and authorizations are managed, incorporating the principles of least privilege and separation of duties",
                        "category": "Protect"
                    },
                    "PR.DS-1": {
                        "name": "Data-at-rest protection",
                        "description": "Data-at-rest is protected",
                        "category": "Protect"
                    }
                }
            },
            "OWASP": {
                "name": "OWASP Top 10",
                "controls": {
                    "A02:2021": {
                        "name": "Cryptographic Failures",
                        "description": "Failures related to cryptography which often leads to sensitive data exposure",
                        "category": "Security Risk"
                    },
                    "A07:2021": {
                        "name": "Identification and Authentication Failures",
                        "description": "Confirmation of the user's identity, authentication, and session management is critical to protect against authentication-related attacks",
                        "category": "Security Risk"
                    }
                }
            },
            "PCI_DSS": {
                "name": "PCI DSS v4.0",
                "controls": {
                    "8.2.1": {
                        "name": "Strong Cryptography for Authentication",
                        "description": "Strong cryptography is used to render all authentication credentials unreadable during transmission and storage",
                        "category": "Access Control"
                    },
                    "8.3.2": {
                        "name": "Secure Authentication Credentials",
                        "description": "Strong authentication credentials are properly managed",
                        "category": "Access Control"
                    }
                }
            },
            "SOC2": {
                "name": "SOC 2 Type II",
                "controls": {
                    "CC6.1": {
                        "name": "Logical and Physical Access Controls",
                        "description": "The entity implements logical access security software, infrastructure, and architectures over protected information assets",
                        "category": "Security"
                    },
                    "CC6.7": {
                        "name": "Encryption of Data",
                        "description": "The entity restricts transmission, movement, and removal of information to authorized internal and external users and processes",
                        "category": "Security"
                    }
                }
            }
        }
    
    def map_to_frameworks(self, exposed_secrets: List[Dict], risk_scores: List[Dict]) -> List[Dict]:
        """
        Map exposed secrets to compliance framework violations
        """
        if not exposed_secrets:
            return []
        
        mappings = []
        
        # ISO 27001 Mapping
        iso_violations = self._map_to_iso27001(exposed_secrets, risk_scores)
        if iso_violations:
            mappings.append({
                "framework": "ISO_27001",
                "framework_name": self.frameworks["ISO_27001"]["name"],
                "controls": [v["control_id"] for v in iso_violations],  # This is the missing field
                "violated_controls": iso_violations,
                "total_violations": len(iso_violations),
                "compliance_status": "NON_COMPLIANT",
                "severity": self._calculate_severity(risk_scores)
            })
        
        # NIST CSF Mapping
        nist_violations = self._map_to_nist(exposed_secrets, risk_scores)
        if nist_violations:
            mappings.append({
                "framework": "NIST_CSF",
                "framework_name": self.frameworks["NIST_CSF"]["name"],
                "controls": [v["control_id"] for v in nist_violations],  # This is the missing field
                "violated_controls": nist_violations,
                "total_violations": len(nist_violations),
                "compliance_status": "NON_COMPLIANT",
                "severity": self._calculate_severity(risk_scores)
            })
        
        # OWASP Mapping
        owasp_violations = self._map_to_owasp(exposed_secrets, risk_scores)
        if owasp_violations:
            mappings.append({
                "framework": "OWASP",
                "framework_name": self.frameworks["OWASP"]["name"],
                "controls": [v["control_id"] for v in owasp_violations],  # This is the missing field
                "violated_controls": owasp_violations,
                "total_violations": len(owasp_violations),
                "compliance_status": "NON_COMPLIANT",
                "severity": self._calculate_severity(risk_scores)
            })
        
        # PCI DSS Mapping (if payment-related secrets found)
        if self._has_payment_secrets(exposed_secrets):
            pci_violations = self._map_to_pci_dss(exposed_secrets, risk_scores)
            if pci_violations:
                mappings.append({
                    "framework": "PCI_DSS",
                    "framework_name": self.frameworks["PCI_DSS"]["name"],
                    "controls": [v["control_id"] for v in pci_violations],  # This is the missing field
                    "violated_controls": pci_violations,
                    "total_violations": len(pci_violations),
                    "compliance_status": "NON_COMPLIANT",
                    "severity": "CRITICAL"
                })
        
        # SOC 2 Mapping
        soc2_violations = self._map_to_soc2(exposed_secrets, risk_scores)
        if soc2_violations:
            mappings.append({
                "framework": "SOC2",
                "framework_name": self.frameworks["SOC2"]["name"],
                "controls": [v["control_id"] for v in soc2_violations],  # This is the missing field
                "violated_controls": soc2_violations,
                "total_violations": len(soc2_violations),
                "compliance_status": "NON_COMPLIANT",
                "severity": self._calculate_severity(risk_scores)
            })
        
        return mappings
    
    def _map_to_iso27001(self, secrets: List[Dict], risks: List[Dict]) -> List[Dict]:
        """Map to ISO 27001 controls"""
        violations = []
        
        # A.9.4.1 - Information access restriction
        violations.append({
            "control_id": "A.9.4.1",
            "control_name": self.frameworks["ISO_27001"]["controls"]["A.9.4.1"]["name"],
            "description": self.frameworks["ISO_27001"]["controls"]["A.9.4.1"]["description"],
            "violation": f"Found {len(secrets)} exposed credentials that could allow unauthorized information access",
            "remediation": "Implement proper access controls and remove hardcoded credentials immediately"
        })
        
        # A.9.4.2 - Secure log-on procedures
        violations.append({
            "control_id": "A.9.4.2",
            "control_name": self.frameworks["ISO_27001"]["controls"]["A.9.4.2"]["name"],
            "description": self.frameworks["ISO_27001"]["controls"]["A.9.4.2"]["description"],
            "violation": "Hardcoded credentials bypass secure log-on procedures",
            "remediation": "Use secure credential management systems and environment variables"
        })
        
        # A.10.1.2 - Key management
        violations.append({
            "control_id": "A.10.1.2",
            "control_name": self.frameworks["ISO_27001"]["controls"]["A.10.1.2"]["name"],
            "description": self.frameworks["ISO_27001"]["controls"]["A.10.1.2"]["description"],
            "violation": "API keys and secrets are not properly managed throughout their lifecycle",
            "remediation": "Implement a key management system with proper rotation and lifecycle policies"
        })
        
        return violations
    
    def _map_to_nist(self, secrets: List[Dict], risks: List[Dict]) -> List[Dict]:
        """Map to NIST CSF controls"""
        violations = []
        
        # PR.AC-1
        violations.append({
            "control_id": "PR.AC-1",
            "control_name": self.frameworks["NIST_CSF"]["controls"]["PR.AC-1"]["name"],
            "description": self.frameworks["NIST_CSF"]["controls"]["PR.AC-1"]["description"],
            "violation": f"{len(secrets)} credentials are not properly managed or protected",
            "remediation": "Implement identity and credential management system"
        })
        
        # PR.DS-1
        violations.append({
            "control_id": "PR.DS-1",
            "control_name": self.frameworks["NIST_CSF"]["controls"]["PR.DS-1"]["name"],
            "description": self.frameworks["NIST_CSF"]["controls"]["PR.DS-1"]["description"],
            "violation": "Secrets are stored in plaintext in source code",
            "remediation": "Use encryption and secure storage for all credentials"
        })
        
        return violations
    
    def _map_to_owasp(self, secrets: List[Dict], risks: List[Dict]) -> List[Dict]:
        """Map to OWASP Top 10"""
        violations = []
        
        # A02:2021 - Cryptographic Failures
        violations.append({
            "control_id": "A02:2021",
            "control_name": self.frameworks["OWASP"]["controls"]["A02:2021"]["name"],
            "description": self.frameworks["OWASP"]["controls"]["A02:2021"]["description"],
            "violation": "Sensitive credentials are exposed in plaintext without encryption",
            "remediation": "Encrypt all sensitive data and use secure credential storage"
        })
        
        # A07:2021 - Identification and Authentication Failures
        violations.append({
            "control_id": "A07:2021",
            "control_name": self.frameworks["OWASP"]["controls"]["A07:2021"]["name"],
            "description": self.frameworks["OWASP"]["controls"]["A07:2021"]["description"],
            "violation": "Hardcoded credentials can be used for unauthorized authentication",
            "remediation": "Remove hardcoded credentials and implement proper authentication mechanisms"
        })
        
        return violations
    
    def _map_to_pci_dss(self, secrets: List[Dict], risks: List[Dict]) -> List[Dict]:
        """Map to PCI DSS controls"""
        violations = []
        
        violations.append({
            "control_id": "8.2.1",
            "control_name": self.frameworks["PCI_DSS"]["controls"]["8.2.1"]["name"],
            "description": self.frameworks["PCI_DSS"]["controls"]["8.2.1"]["description"],
            "violation": "Payment processing credentials are not encrypted",
            "remediation": "Encrypt all payment-related credentials using strong cryptography"
        })
        
        violations.append({
            "control_id": "8.3.2",
            "control_name": self.frameworks["PCI_DSS"]["controls"]["8.3.2"]["name"],
            "description": self.frameworks["PCI_DSS"]["controls"]["8.3.2"]["description"],
            "violation": "Payment API credentials are not securely managed",
            "remediation": "Implement secure credential management for all payment systems"
        })
        
        return violations
    
    def _map_to_soc2(self, secrets: List[Dict], risks: List[Dict]) -> List[Dict]:
        """Map to SOC 2 controls"""
        violations = []
        
        violations.append({
            "control_id": "CC6.1",
            "control_name": self.frameworks["SOC2"]["controls"]["CC6.1"]["name"],
            "description": self.frameworks["SOC2"]["controls"]["CC6.1"]["description"],
            "violation": f"{len(secrets)} access credentials are not properly controlled",
            "remediation": "Implement logical access controls and secure credential management"
        })
        
        violations.append({
            "control_id": "CC6.7",
            "control_name": self.frameworks["SOC2"]["controls"]["CC6.7"]["name"],
            "description": self.frameworks["SOC2"]["controls"]["CC6.7"]["description"],
            "violation": "Credentials are not encrypted in storage",
            "remediation": "Encrypt all credentials and implement secure transmission protocols"
        })
        
        return violations
    
    def _has_payment_secrets(self, secrets: List[Dict]) -> bool:
        """Check if any payment-related secrets are exposed"""
        payment_providers = ['stripe', 'paypal', 'square', 'braintree']
        
        for secret in secrets:
            if secret.get('provider', '').lower() in payment_providers:
                return True
        
        return False
    
    def _calculate_severity(self, risk_scores: List[Dict]) -> str:
        """Calculate overall severity based on risk scores"""
        if not risk_scores:
            return "LOW"
        
        max_severity = "LOW"
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        
        for risk in risk_scores:
            severity = risk.get('severity', 'LOW')
            if severity_order.index(severity) > severity_order.index(max_severity):
                max_severity = severity
        
        return max_severity