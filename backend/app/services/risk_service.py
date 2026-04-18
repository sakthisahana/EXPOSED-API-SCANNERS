from typing import Dict
from app.services.github_service import GitHubService


class RiskService:
    """
    Milestone 2: Risk Scoring Engine & Severity Classification
    """
    
    def __init__(self):
        # Risk factor weights
        self.weights = {
            "privilege_level": 40,
            "environment": 30,
            "provider_criticality": 20,
            "exposure_location": 10
        }
        
        # Privilege level scores
        self.privilege_scores = {
            "Critical": 100,
            "High": 80,
            "Medium": 50,
            "Low": 20
        }
        
        # Environment scores
        self.environment_scores = {
            "Live": 100,
            "Production": 100,
            "Test": 30,
            "Development": 20,
            "Unknown": 60
        }
        
        # Provider criticality scores
        self.provider_scores = {
            "AWS": 100,
            "PayPal": 95,
            "Stripe": 90,
            "Square": 90,
            "Twilio": 80,
            "Firebase": 75,
            "Google": 75,
            "GitHub": 70,
            "SendGrid": 60,
            "Mailgun": 60,
            "Slack": 50,
            "Generic": 40
        }
        
        # File location risk
        self.location_scores = {
            "config": 100,
            "env": 100,
            "credentials": 100,
            "secrets": 100,
            "keys": 90,
            "settings": 80,
            "src": 70,
            "lib": 60,
            "test": 30,
            "example": 20,
            "demo": 20
        }
    
    def calculate_risk_score(self, secret: Dict) -> Dict:
        """
        Calculate comprehensive risk score for exposed secret
        """
        factors = {}
        
        # 1. Privilege Level Score (40%)
        privilege = secret.get("privilege_level", "Medium")
        privilege_score = self.privilege_scores.get(privilege, 50)
        factors["privilege_level"] = int(privilege_score * self.weights["privilege_level"] / 100)
        
        # 2. Environment Score (30%)
        environment = secret.get("environment", "Unknown")
        env_score = self._get_environment_score(environment)
        factors["environment"] = int(env_score * self.weights["environment"] / 100)
        
        # 3. Provider Criticality Score (20%)
        provider = secret.get("provider", "Generic")
        provider_score = self.provider_scores.get(provider, 40)
        factors["provider_criticality"] = int(provider_score * self.weights["provider_criticality"] / 100)
        
        # 4. Exposure Location Score (10%)
        file_path = secret.get("file_path", "")
        location_score = self._get_location_score(file_path)
        factors["exposure_location"] = int(location_score * self.weights["exposure_location"] / 100)
        
        # Calculate total score
        total_score = sum(factors.values())
        
        # Determine severity
        severity = self._get_severity(total_score)
        
        # Calculate exploitation probability (simple heuristic)
        exploitation_probability = self._calculate_exploitation_probability(
            total_score,
            environment,
            privilege
        )
        
        return {
            "total_score": total_score,
            "severity": severity,
            "factors": factors,
            "exploitation_probability": exploitation_probability,
            "risk_details": {
                "privilege_impact": privilege,
                "environment_impact": environment,
                "provider_impact": provider,
                "location_impact": self._get_location_category(file_path)
            }
        }
    
    def _get_environment_score(self, environment: str) -> int:
        """
        Get environment risk score
        """
        for key, score in self.environment_scores.items():
            if key.lower() in environment.lower():
                return score
        return self.environment_scores["Unknown"]
    
    def _get_location_score(self, file_path: str) -> int:
        """
        Calculate risk based on file location
        """
        file_path_lower = file_path.lower()
        
        # Check for high-risk locations
        for keyword, score in self.location_scores.items():
            if keyword in file_path_lower:
                return score
        
        # Default score for unrecognized locations
        return 50
    
    def _get_location_category(self, file_path: str) -> str:
        """
        Get location category for reporting
        """
        file_path_lower = file_path.lower()
        
        high_risk_keywords = ["config", "env", "credentials", "secrets", "keys"]
        for keyword in high_risk_keywords:
            if keyword in file_path_lower:
                return "High-Risk Configuration File"
        
        if "test" in file_path_lower or "example" in file_path_lower:
            return "Test/Example File"
        
        return "Source Code File"
    
    def _get_severity(self, score: int) -> str:
        """
        Determine severity level based on total score
        """
        if score >= 85:
            return "CRITICAL"
        elif score >= 65:
            return "HIGH"
        elif score >= 40:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _calculate_exploitation_probability(
        self,
        score: int,
        environment: str,
        privilege: str
    ) -> float:
        """
        Calculate probability of exploitation (0.0 - 1.0)
        """
        base_probability = score / 100.0
        
        # Adjust for environment
        if "live" in environment.lower() or "production" in environment.lower():
            base_probability *= 1.2
        elif "test" in environment.lower():
            base_probability *= 0.6
        
        # Adjust for privilege
        if privilege == "Critical":
            base_probability *= 1.3
        elif privilege == "Low":
            base_probability *= 0.7
        
        # Cap at 1.0
        return min(1.0, base_probability)
    
    def get_risk_summary(self, risk_scores: list) -> Dict:
        """
        Generate summary of all risks
        """
        if not risk_scores:
            return {
                "total_risks": 0,
                "average_score": 0,
                "highest_risk": 0,
                "severity_distribution": {}
            }
        
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        total_score = 0
        highest_score = 0
        
        for risk in risk_scores:
            severity_counts[risk["severity"]] += 1
            total_score += risk["total_score"]
            highest_score = max(highest_score, risk["total_score"])
        
        return {
            "total_risks": len(risk_scores),
            "average_score": total_score / len(risk_scores),
            "highest_risk": highest_score,
            "severity_distribution": severity_counts
        }