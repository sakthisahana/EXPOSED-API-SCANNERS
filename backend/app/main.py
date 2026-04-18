from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict, Optional, Any
import uvicorn

# Correct service imports
from app.services.github_service import GitHubService
from app.services.scanner_service import ScannerService
from app.services.risk_service import RiskService
from app.services.ai_service import AIService
from app.services.compliance_service import ComplianceService

app = FastAPI(
    title="Risk-Based API Scanner",
    description="AI-Driven API Key Exposure Scanner with Risk Prediction",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173", "*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize services
github_service = GitHubService()
scanner_service = ScannerService()
risk_service = RiskService()
ai_service = AIService()
compliance_service = ComplianceService()

# ==========================
# Request / Response Models
# ==========================

class ScanRequest(BaseModel):
    repository_url: str

class RepositoryInfo(BaseModel):
    url: str
    is_public: bool
    owner: str
    repo_name: str
    scan_allowed: bool
    full_name: Optional[str] = None # Added for frontend mapping

class ExposedSecret(BaseModel):
    file_path: str
    line_number: int
    secret_type: str
    provider: str
    environment: str
    privilege_level: str
    masked_value: str
    context: str

class RiskScore(BaseModel):
    total_score: int
    severity: str
    factors: Dict[str, int]
    exploitation_probability: float

class MitigationSuggestion(BaseModel):
    priority: str
    action: str
    description: str

# --- UPDATED COMPLIANCE MODELS FOR FRONTEND SYNC ---
class ViolatedControl(BaseModel):
    control_id: str
    control_name: str
    description: str
    violation: str
    remediation: str

class ComplianceMapping(BaseModel):
    framework: str
    framework_name: str # Added
    compliance_status: str
    total_violations: int # Added
    violated_controls: List[ViolatedControl] # Added: dashboard needs this detail
    severity: Optional[str] = "LOW"

class ScanResult(BaseModel):
    repository_info: RepositoryInfo
    exposed_secrets: List[ExposedSecret]
    risk_scores: List[RiskScore]
    ai_predictions: Dict[str, Any]
    mitigation_suggestions: List[MitigationSuggestion]
    compliance_mappings: List[ComplianceMapping]
    summary: Dict[str, Any]

# ==========================
# Routes
# ==========================

@app.get("/")
async def root():
    return {
        "message": "Risk-Based API Scanner API",
        "version": "1.0.0",
        "status": "online"
    }

@app.get("/health")
async def health_check():
    return {"status": "healthy"}

@app.post("/api/validate-repository")
async def validate_repository(request: ScanRequest):
    try:
        repo_info = github_service.validate_repository(request.repository_url)
        return repo_info
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/scan", response_model=ScanResult)
async def scan_repository(request: ScanRequest):
    try:
        print(f"Starting scan for: {request.repository_url}")
        
        # Step 1: Validate repository
        repo_info = github_service.validate_repository(request.repository_url)
        
        if not repo_info["scan_allowed"]:
            raise HTTPException(
                status_code=403,
                detail="Repository is private. Only public repositories can be scanned."
            )

        # Step 2: Scan for exposed secrets
        exposed_secrets = scanner_service.scan_repository(
            repo_info["owner"],
            repo_info["repo_name"]
        )

        if not exposed_secrets:
            return ScanResult(
                repository_info=repo_info,
                exposed_secrets=[],
                risk_scores=[],
                ai_predictions={},
                mitigation_suggestions=[],
                compliance_mappings=[],
                summary={
                    "total_secrets": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "overall_risk": "NONE"
                }
            )

        # Step 3: Calculate risk scores
        risk_scores = [
            risk_service.calculate_risk_score(secret)
            for secret in exposed_secrets
        ]

        # Step 4: AI predictions
        ai_predictions = ai_service.predict_risks(exposed_secrets, risk_scores)

        # Step 5: Mitigation suggestions
        mitigation_suggestions = ai_service.generate_mitigations(
            exposed_secrets, risk_scores, ai_predictions
        )

        # Step 6: Compliance mapping (Ensure service returns new structure)
        compliance_mappings = compliance_service.map_to_frameworks(
            exposed_secrets, risk_scores
        )

        # Step 7: Summary calculation
        severity_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        summary = {
            "total_secrets": len(exposed_secrets),
            "critical_count": sum(1 for r in risk_scores if r["severity"] == "CRITICAL"),
            "high_count": sum(1 for r in risk_scores if r["severity"] == "HIGH"),
            "medium_count": sum(1 for r in risk_scores if r["severity"] == "MEDIUM"),
            "low_count": sum(1 for r in risk_scores if r["severity"] == "LOW"),
            "overall_risk": max(
                [r["severity"] for r in risk_scores],
                key=lambda x: severity_order.index(x)
            )
        }

        return ScanResult(
            repository_info=repo_info,
            exposed_secrets=exposed_secrets,
            risk_scores=risk_scores,
            ai_predictions=ai_predictions,
            mitigation_suggestions=mitigation_suggestions,
            compliance_mappings=compliance_mappings,
            summary=summary
        )

    except HTTPException:
        raise
    except Exception as e:
        print(f"Error during scan: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/train-ai-model")
async def train_ai_model():
    try:
        return ai_service.train_model()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/statistics")
async def get_statistics():
    return {
        "total_scans": 0,
        "total_secrets_found": 0,
        "most_common_provider": "Generic API",
        "average_risk_score": 0
    }

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)