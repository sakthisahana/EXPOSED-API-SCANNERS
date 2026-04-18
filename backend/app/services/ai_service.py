import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib
import os
from typing import Dict, List
from app.services.github_service import GitHubService


class AIService:
    """
    Milestone 3: AI-Based Risk Prediction & Mitigation
    """
    
    def __init__(self):
        self.model = None
        self.label_encoders = {}
        self.model_path = "models/risk_predictor.pkl"
        self.encoders_path = "models/label_encoders.pkl"
        
        # Try to load existing model
        self._load_model()
    
    def _load_model(self):
        """
        Load pre-trained model if exists
        """
        try:
            if os.path.exists(self.model_path):
                self.model = joblib.load(self.model_path)
                self.label_encoders = joblib.load(self.encoders_path)
        except Exception as e:
            print(f"Could not load model: {e}")
            self.model = None
    
    def train_model(self):
        """
        Train AI model with synthetic training data
        """
        # Generate synthetic training data
        X_train, y_train = self._generate_training_data()
        
        # Train Random Forest Classifier
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        self.model.fit(X_train, y_train)
        
        # Save model
        os.makedirs("models", exist_ok=True)
        joblib.dump(self.model, self.model_path)
        joblib.dump(self.label_encoders, self.encoders_path)
        
        return {
            "status": "success",
            "message": "AI model trained successfully",
            "samples": len(X_train),
            "accuracy": "N/A (synthetic data)"
        }
    
    def _generate_training_data(self):
        """
        Generate synthetic training data for the model
        """
        np.random.seed(42)
        
        # Features: [privilege_score, environment_score, provider_score, location_score]
        samples = []
        labels = []
        
        # Generate 1000 synthetic samples
        for _ in range(1000):
            privilege = np.random.choice([20, 50, 80, 100])
            environment = np.random.choice([20, 30, 60, 100])
            provider = np.random.choice([40, 60, 80, 100])
            location = np.random.choice([20, 50, 70, 100])
            
            total_score = (
                privilege * 0.4 +
                environment * 0.3 +
                provider * 0.2 +
                location * 0.1
            )
            
            # Label: exploitation likelihood (0: Low, 1: Medium, 2: High, 3: Critical)
            if total_score >= 85:
                label = 3
            elif total_score >= 65:
                label = 2
            elif total_score >= 40:
                label = 1
            else:
                label = 0
            
            samples.append([privilege, environment, provider, location])
            labels.append(label)
        
        return np.array(samples), np.array(labels)
    
    def predict_risks(self, exposed_secrets: List[Dict], risk_scores: List[Dict]) -> Dict:
        """
        Predict exploitation risks using AI
        """
        if not self.model:
            # Train model if not exists
            self.train_model()
        
        predictions = []
        
        for i, (secret, risk) in enumerate(zip(exposed_secrets, risk_scores)):
            # Extract features
            features = self._extract_features(risk)
            
            # Predict
            prediction = self.model.predict([features])[0]
            probability = self.model.predict_proba([features])[0]
            
            predictions.append({
                "secret_index": i,
                "predicted_risk_level": self._get_risk_level_name(prediction),
                "confidence": float(max(probability)),
                "probability_distribution": {
                    "low": float(probability[0]),
                    "medium": float(probability[1]),
                    "high": float(probability[2]),
                    "critical": float(probability[3])
                }
            })
        
        # Calculate trends
        trends = self._analyze_trends(predictions)
        
        return {
            "predictions": predictions,
            "trends": trends,
            "model_info": {
                "model_type": "Random Forest Classifier",
                "features_used": ["privilege", "environment", "provider", "location"]
            }
        }
    
    def _extract_features(self, risk: Dict) -> List[float]:
        """
        Extract features for prediction
        """
        factors = risk["factors"]
        return [
            factors["privilege_level"],
            factors["environment"],
            factors["provider_criticality"],
            factors["exposure_location"]
        ]
    
    def _get_risk_level_name(self, prediction: int) -> str:
        """
        Convert prediction to risk level name
        """
        levels = ["Low", "Medium", "High", "Critical"]
        return levels[prediction]
    
    def _analyze_trends(self, predictions: List[Dict]) -> Dict:
        """
        Analyze risk trends across predictions
        """
        if not predictions:
            return {}
        
        risk_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
        total_confidence = 0
        
        for pred in predictions:
            risk_counts[pred["predicted_risk_level"]] += 1
            total_confidence += pred["confidence"]
        
        return {
            "risk_distribution": risk_counts,
            "average_confidence": total_confidence / len(predictions),
            "most_likely_risk": max(risk_counts, key=risk_counts.get),
            "total_predictions": len(predictions)
        }
    
    def generate_mitigations(
        self,
        exposed_secrets: List[Dict],
        risk_scores: List[Dict],
        ai_predictions: Dict
    ) -> List[Dict]:
        """
        Generate AI-driven mitigation suggestions
        """
        mitigations = []
        
        for i, (secret, risk) in enumerate(zip(exposed_secrets, risk_scores)):
            severity = risk["severity"]
            provider = secret["provider"]
            environment = secret["environment"]
            
            suggestions = self._get_mitigation_actions(
                severity,
                provider,
                environment,
                secret
            )
            
            mitigations.extend(suggestions)
        
        # Remove duplicates and prioritize
        mitigations = self._prioritize_mitigations(mitigations)
        
        return mitigations
    
    def _get_mitigation_actions(
        self,
        severity: str,
        provider: str,
        environment: str,
        secret: Dict
    ) -> List[Dict]:
        """
        Get specific mitigation actions based on context
        """
        actions = []
        
        # Critical/High severity actions
        if severity in ["CRITICAL", "HIGH"]:
            actions.append({
                "priority": "IMMEDIATE",
                "action": "Revoke API Key",
                "description": f"Immediately revoke the exposed {provider} API key and generate a new one. The key is in {environment} environment.",
                "steps": [
                    f"1. Login to {provider} dashboard",
                    "2. Navigate to API keys section",
                    "3. Revoke the exposed key",
                    "4. Generate new key with minimum required permissions",
                    "5. Update application configuration"
                ]
            })
            
            actions.append({
                "priority": "IMMEDIATE",
                "action": "Review Access Logs",
                "description": f"Check {provider} access logs for any unauthorized usage",
                "steps": [
                    "1. Access security/audit logs",
                    "2. Look for unusual activity patterns",
                    "3. Check for unauthorized API calls",
                    "4. Document any suspicious activity"
                ]
            })
        
        # All severity levels
        actions.append({
            "priority": "HIGH",
            "action": "Implement Environment Variables",
            "description": "Move API keys from source code to environment variables",
            "steps": [
                "1. Create .env file (add to .gitignore)",
                "2. Store API keys in .env",
                "3. Use environment variable loader (dotenv)",
                "4. Remove hardcoded keys from source",
                "5. Update deployment configuration"
            ]
        })
        
        actions.append({
            "priority": "HIGH",
            "action": "Use Secrets Management",
            "description": "Implement proper secrets management solution",
            "steps": [
                "1. Choose secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.)",
                "2. Store API keys in secrets manager",
                "3. Update application to fetch from secrets manager",
                "4. Implement proper access controls",
                "5. Enable rotation policies"
            ]
        })
        
        # Add to .gitignore
        actions.append({
            "priority": "MEDIUM",
            "action": "Update .gitignore",
            "description": "Prevent future exposure by updating .gitignore",
            "steps": [
                "1. Add .env to .gitignore",
                "2. Add config files to .gitignore",
                "3. Add credentials directory to .gitignore",
                "4. Commit .gitignore changes"
            ]
        })
        
        # Git history cleanup (be careful with this)
        if severity in ["CRITICAL", "HIGH"]:
            actions.append({
                "priority": "MEDIUM",
                "action": "Clean Git History (Optional)",
                "description": "Remove secrets from Git history - WARNING: This rewrites history",
                "steps": [
                    "1. Backup repository",
                    "2. Use git-filter-repo or BFG Repo-Cleaner",
                    "3. Force push changes (coordinate with team)",
                    "4. Re-clone repository for all developers"
                ],
                "warning": "This is destructive and affects all collaborators"
            })
        
        return actions
    
    def _prioritize_mitigations(self, mitigations: List[Dict]) -> List[Dict]:
        """
        Remove duplicates and sort by priority
        """
        # Remove duplicates based on action name
        seen = set()
        unique_mitigations = []
        
        for mitigation in mitigations:
            action = mitigation["action"]
            if action not in seen:
                seen.add(action)
                unique_mitigations.append(mitigation)
        
        # Sort by priority
        priority_order = {"IMMEDIATE": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        unique_mitigations.sort(key=lambda x: priority_order.get(x["priority"], 4))
        
        return unique_mitigations