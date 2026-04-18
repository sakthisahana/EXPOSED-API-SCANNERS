import re
from typing import List, Dict
from app.services.github_service import GitHubService


class ScannerService:
    """
    Milestone 1: Source Code Scanning & Exposure Detection
    """
    
    def __init__(self):
        self.github_service = GitHubService()
        
        # API Key patterns with provider identification
        self.patterns = {
            "stripe_live": {
                "pattern": r'sk_live_[0-9a-zA-Z]{24,}',
                "provider": "Stripe",
                "environment": "Live",
                "privilege": "High"
            },
            "stripe_test": {
                "pattern": r'sk_test_[0-9a-zA-Z]{24,}',
                "provider": "Stripe",
                "environment": "Test",
                "privilege": "Low"
            },
            "stripe_restricted": {
                "pattern": r'rk_(live|test)_[0-9a-zA-Z]{24,}',
                "provider": "Stripe",
                "environment": "Live/Test",
                "privilege": "Medium"
            },
            "stripe_publishable": {
                "pattern": r'pk_(live|test)_[0-9a-zA-Z]{24,}',
                "provider": "Stripe",
                "environment": "Live/Test",
                "privilege": "Medium"
            },
            "aws_access_key": {
                "pattern": r'AKIA[0-9A-Z]{16}',
                "provider": "AWS",
                "environment": "Live",
                "privilege": "Critical"
            },
            "aws_secret_key": {
                "pattern": r'[A-Za-z0-9/+=]{40}',
                "provider": "AWS",
                "environment": "Live",
                "privilege": "Critical",
                "context_keywords": ["aws", "secret", "access_key"]
            },
            "firebase": {
                "pattern": r'AIza[0-9A-Za-z\-_]{35}',
                "provider": "Firebase",
                "environment": "Live",
                "privilege": "High"
            },
            "google_api": {
                "pattern": r'AIza[0-9A-Za-z\-_]{35}',
                "provider": "Google",
                "environment": "Live",
                "privilege": "High"
            },
            "github_token": {
                "pattern": r'gh[pousr]_[0-9a-zA-Z]{36,}',
                "provider": "GitHub",
                "environment": "Live",
                "privilege": "High"
            },
            "github_oauth": {
                "pattern": r'gho_[0-9a-zA-Z]{36,}',
                "provider": "GitHub",
                "environment": "Live",
                "privilege": "High"
            },
            "slack_token": {
                "pattern": r'xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[0-9a-zA-Z]{24,}',
                "provider": "Slack",
                "environment": "Live",
                "privilege": "Medium"
            },
            "slack_webhook": {
                "pattern": r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24,}',
                "provider": "Slack",
                "environment": "Live",
                "privilege": "Medium"
            },
            "sendgrid": {
                "pattern": r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
                "provider": "SendGrid",
                "environment": "Live",
                "privilege": "Medium"
            },
            "mailgun": {
                "pattern": r'key-[0-9a-zA-Z]{32}',
                "provider": "Mailgun",
                "environment": "Live",
                "privilege": "Medium"
            },
            "twilio": {
                "pattern": r'SK[0-9a-fA-F]{32}',
                "provider": "Twilio",
                "environment": "Live",
                "privilege": "High"
            },
            "twilio_account": {
                "pattern": r'AC[0-9a-fA-F]{32}',
                "provider": "Twilio",
                "environment": "Live",
                "privilege": "High"
            },
            "paypal": {
                "pattern": r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',
                "provider": "PayPal",
                "environment": "Live",
                "privilege": "Critical"
            },
            "square": {
                "pattern": r'sq0atp-[0-9A-Za-z\-_]{22,}',
                "provider": "Square",
                "environment": "Live",
                "privilege": "High"
            },
            "square_secret": {
                "pattern": r'sq0csp-[0-9A-Za-z\-_]{43,}',
                "provider": "Square",
                "environment": "Live",
                "privilege": "Critical"
            },
            "private_key_rsa": {
                "pattern": r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----',
                "provider": "Generic",
                "environment": "Live",
                "privilege": "Critical"
            },
            "jwt_token": {
                "pattern": r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
                "provider": "Generic JWT",
                "environment": "Unknown",
                "privilege": "Medium"
            },
            # AGGRESSIVE PATTERNS - Will catch most API keys
            "uuid_api_key": {
                "pattern": r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}',
                "provider": "Generic API",
                "environment": "Unknown",
                "privilege": "Low",
                "context_keywords": ["api", "key", "token", "secret", "password", "credential", "auth"]
            },
            "generic_api_key_with_context": {
                "pattern": r'["\']?([A-Za-z0-9_\-]{20,})["\']?',
                "provider": "Generic API",
                "environment": "Unknown",
                "privilege": "Low",
                "context_keywords": ["api_key", "apikey", "api-key", "secret", "token", "password", "key"]
            },
            "hex_api_key": {
                "pattern": r'[0-9a-fA-F]{32,}',
                "provider": "Generic API",
                "environment": "Unknown",
                "privilege": "Low",
                "context_keywords": ["api", "key", "token", "secret"]
            }
        }
    
    def scan_repository(self, owner: str, repo_name: str) -> List[Dict]:
        """
        Scan entire repository for exposed secrets
        """
        exposed_secrets = []
        
        # Get all files
        files = self.github_service.get_repository_files(owner, repo_name)
        
        print(f"Found {len(files)} scannable files")
        
        for file_info in files:
            try:
                # Download file content
                content = self.github_service.get_file_content(file_info["download_url"])
                
                if not content:
                    print(f"Skipping {file_info['path']} - no content")
                    continue
                
                print(f"Scanning {file_info['path']}...")
                
                # Scan file content
                secrets = self.scan_file_content(
                    content,
                    file_info["path"],
                    file_info["name"]
                )
                
                if secrets:
                    print(f"✓ Found {len(secrets)} secret(s) in {file_info['path']}")
                
                exposed_secrets.extend(secrets)
                
            except Exception as e:
                print(f"Error scanning file {file_info['path']}: {str(e)}")
                continue
        
        print(f"\nTotal secrets found: {len(exposed_secrets)}")
        return exposed_secrets
    
    def scan_file_content(self, content: str, file_path: str, file_name: str) -> List[Dict]:
        """
        Scan individual file content for API keys
        """
        secrets = []
        lines = content.split('\n')
        found_secrets = set()  # To avoid duplicates
        
        for secret_type, config in self.patterns.items():
            pattern = config["pattern"]
            
            for line_num, line in enumerate(lines, start=1):
                # Skip empty lines
                if not line.strip():
                    continue
                
                try:
                    matches = re.finditer(pattern, line)
                    
                    for match in matches:
                        # Extract the matched secret
                        secret_value = match.group(0)
                        
                        # Skip very short matches for generic patterns
                        if len(secret_value) < 8:
                            continue
                        
                        # Check if we need context keywords
                        if config.get("context_keywords"):
                            if not self._has_context_keywords(line, content, config["context_keywords"]):
                                continue
                        
                        # Create unique identifier to avoid duplicates
                        secret_id = f"{file_path}:{line_num}:{secret_value}"
                        if secret_id in found_secrets:
                            continue
                        found_secrets.add(secret_id)
                        
                        # Skip if it's obviously a comment AND looks fake
                        in_comment = self._is_in_comment(line, match.start())
                        
                        # Validate the secret
                        is_valid, validation_result = self._validate_secret(secret_value, secret_type, line)
                        
                        # Skip obvious false positives only if in comment
                        if in_comment and not is_valid and self._is_obvious_example(secret_value, line):
                            continue
                        
                        # Mask the secret
                        masked_value = self._mask_secret(secret_value)
                        
                        # Get context (surrounding code)
                        context = self._get_context(lines, line_num)
                        
                        # Determine actual privilege based on validation
                        actual_privilege = config["privilege"]
                        if not is_valid:
                            actual_privilege = "Low"  # Downgrade if not valid
                        
                        print(f"  → Found {secret_type} at line {line_num}: {masked_value}")
                        
                        secrets.append({
                            "file_path": file_path,
                            "file_name": file_name,
                            "line_number": line_num,
                            "secret_type": secret_type,
                            "provider": config["provider"],
                            "environment": config["environment"],
                            "privilege_level": actual_privilege,
                            "masked_value": masked_value,
                            "context": context,
                            "exposure_type": "Hardcoded",
                            "is_valid": is_valid,
                            "validation_result": validation_result
                        })
                        
                except Exception as e:
                    print(f"  Error processing line {line_num}: {str(e)}")
                    continue
        
        return secrets
    
    def _has_context_keywords(self, line: str, content: str, keywords: List[str]) -> bool:
        """
        Check if line or nearby content has required context keywords
        """
        # Check in the line itself
        line_lower = line.lower()
        for keyword in keywords:
            if keyword.lower() in line_lower:
                return True
        
        # Check in nearby lines (within 3 lines)
        lines = content.split('\n')
        for i, content_line in enumerate(lines):
            if line.strip() in content_line:
                # Check surrounding lines
                start = max(0, i - 3)
                end = min(len(lines), i + 4)
                nearby_text = ' '.join(lines[start:end]).lower()
                
                for keyword in keywords:
                    if keyword.lower() in nearby_text:
                        return True
        
        return False
    
    def _validate_secret(self, secret_value: str, secret_type: str, line: str) -> tuple:
        """
        Validate if the secret appears to be legitimate
        Returns: (is_valid: bool, validation_message: str)
        """
        secret_lower = secret_value.lower()
        line_lower = line.lower()
        
        # Known fake/example patterns
        fake_patterns = [
            'example', 'sample', 'dummy', 'test', 'your_', 'your-',
            'placeholder', 'xxxxxxxx', '12345678', 'abcdefgh', 
            'mock', 'fake', 'demo', 'undefined', 'null'
        ]
        
        # Check if it contains fake patterns
        for pattern in fake_patterns:
            if pattern in secret_lower:
                return (False, f"Contains example pattern: '{pattern}'")
        
        # Check line context for fake indicators
        for pattern in fake_patterns:
            if pattern in line_lower:
                return (False, f"Line contains example indicator: '{pattern}'")
        
        # Check for repeated characters (like AAAAAAA...)
        if len(set(secret_value)) < max(len(secret_value) / 4, 3):
            return (False, "Contains too many repeated characters")
        
        # Check for sequential patterns
        if any(seq in secret_value.upper() for seq in ['ABCD', '1234', 'QWER', '0000', '1111']):
            return (False, "Contains sequential patterns")
        
        # UUID pattern is usually legit if in right context
        if re.match(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$', secret_value):
            if any(word in line_lower for word in ['api', 'key', 'secret', 'token', 'password']):
                return (True, "Valid UUID format with API context")
            return (False, "UUID without clear API context")
        
        # If it looks like a random string with good entropy, likely valid
        unique_chars = len(set(secret_value))
        if unique_chars > len(secret_value) / 2:
            return (True, "Good entropy - appears to be valid")
        
        return (False, "Low entropy - possibly not a real credential")
    
    def _is_obvious_example(self, secret_value: str, line: str) -> bool:
        """
        Check if this is obviously an example value
        """
        obvious_examples = [
            'example.com',
            'test.com',
            'yourdomain',
            'YOUR_',
            'INSERT_',
            'REPLACE_',
            '<your',
            '<insert',
            'xxx',
            '***'
        ]
        
        for example in obvious_examples:
            if example.lower() in secret_value.lower() or example.lower() in line.lower():
                return True
        
        return False
    
    def _mask_secret(self, secret: str) -> str:
        """
        Mask secret value for display
        """
        if len(secret) <= 8:
            return "*" * len(secret)
        
        if len(secret) <= 16:
            visible_chars = 3
        else:
            visible_chars = 4
            
        return secret[:visible_chars] + "*" * (len(secret) - visible_chars * 2) + secret[-visible_chars:]
    
    def _is_in_comment(self, line: str, position: int) -> bool:
        """
        Check if the match is within a comment
        """
        # Check for common comment patterns
        line_before_match = line[:position].strip()
        
        comment_indicators = [
            '//', '#', '/*', '*', '<!--', '//'
        ]
        
        for indicator in comment_indicators:
            if indicator in line_before_match:
                return True
        
        return False
    
    def _get_context(self, lines: List[str], line_num: int, context_size: int = 2) -> str:
        """
        Get surrounding lines for context
        """
        start = max(0, line_num - context_size - 1)
        end = min(len(lines), line_num + context_size)
        
        context_lines = []
        for i in range(start, end):
            prefix = "→ " if i == line_num - 1 else "  "
            line_content = lines[i][:150] if len(lines[i]) > 150 else lines[i]
            context_lines.append(f"{prefix}{line_content}")
        
        return "\n".join(context_lines)