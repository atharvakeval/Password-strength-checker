from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import joblib
import re
from pathlib import Path
from urllib.parse import urlparse
from scipy.sparse import hstack, csr_matrix
import uvicorn

app = FastAPI(
    title="AI Phishing Email Detector",
    description="ML-powered API for detecting phishing emails",
    version="1.0.0"
)

# ── CORS: Allow the Chrome extension to call the API ──────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],          # Restrict to specific extension IDs in production
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# ── Load models with absolute path resolution ─────────────────────────────────
BASE_DIR = Path(__file__).resolve().parent.parent  # → backend/
MODEL_DIR = BASE_DIR / "models"

try:
    model = joblib.load(MODEL_DIR / "phishing_detector_model.pkl")
    vectorizer = joblib.load(MODEL_DIR / "tfidf_vectorizer.pkl")
    feature_columns = joblib.load(MODEL_DIR / "feature_columns.pkl")
    MODEL_LOADED = True
except Exception as e:
    print(f"⚠️  Could not load models: {e}")
    MODEL_LOADED = False
    model = vectorizer = feature_columns = None


# ── Schemas ───────────────────────────────────────────────────────────────────

class EmailRequest(BaseModel):
    text: str
    sender: str = None
    subject: str = None

class PredictionResponse(BaseModel):
    is_phishing: bool
    confidence: float
    risk_score: float
    indicators: list
    explanation: str


# ── Feature engineering ───────────────────────────────────────────────────────

URGENCY_WORDS = [
    "urgent", "immediately", "alert", "warning", "suspended",
    "verify", "confirm", "action required", "expires", "limited time"
]
FINANCIAL_WORDS = [
    "password", "credit card", "bank", "account", "login",
    "ssn", "social security", "payment", "invoice", "wire transfer"
]
SUSPICIOUS_DOMAIN_KWS = ["verify", "secure", "account", "login", "update", "confirm", "banking"]
SPELLING_ERROR_PATTERN = re.compile(
    r"\b(acount|verfy|confim|logn|pasword|securty)\b", re.IGNORECASE
)
URL_PATTERN = re.compile(r"https?://[^\s]+")


def extract_features(text: str) -> list:
    """Extract phishing-specific numeric features."""
    if feature_columns is None:
        return []

    text_lower = text.lower()
    features: dict = {}

    features["text_length"] = len(text)
    features["num_words"] = len(text.split())
    features["num_exclamation"] = text.count("!")
    features["num_capitals"] = sum(1 for c in text if c.isupper())
    features["capital_ratio"] = features["num_capitals"] / len(text) if text else 0
    features["urgency_score"] = sum(1 for w in URGENCY_WORDS if w in text_lower)
    features["financial_score"] = sum(1 for w in FINANCIAL_WORDS if w in text_lower)
    features["has_url"] = 1 if "http" in text_lower else 0

    urls = URL_PATTERN.findall(text)
    features["num_urls"] = len(urls)

    suspicious_domains = 0
    for url in urls:
        try:
            domain = urlparse(url).netloc.lower()
            if any(kw in domain for kw in SUSPICIOUS_DOMAIN_KWS):
                suspicious_domains += 1
        except Exception:
            pass

    features["suspicious_domains"] = suspicious_domains
    features["ip_in_url"] = 0
    features["short_urls"] = 0
    features["num_spelling_errors"] = len(SPELLING_ERROR_PATTERN.findall(text))
    features["has_html"] = 1 if "<html" in text_lower else 0
    features["has_script"] = 1 if "<script" in text_lower else 0

    return [features.get(col, 0) for col in feature_columns]


def get_indicators(text: str) -> list:
    """Return human-readable phishing indicators found in the email."""
    indicators = []
    text_lower = text.lower()

    found_urgency = [w for w in URGENCY_WORDS[:5] if w in text_lower]
    if found_urgency:
        indicators.append(f"⚠️ Urgency keywords: {', '.join(found_urgency)}")

    urls = URL_PATTERN.findall(text)
    if urls:
        indicators.append(f"🔗 Contains {len(urls)} link(s): {urls[0][:60]}…")

    found_financial = [w for w in ["password", "verify", "account", "login", "bank"] if w in text_lower]
    if found_financial:
        indicators.append(f"💳 Financial/security terms: {', '.join(found_financial)}")

    caps_ratio = sum(1 for c in text if c.isupper()) / len(text) if text else 0
    if caps_ratio > 0.1:
        indicators.append(f"📢 Excessive capitalisation ({caps_ratio:.1%} of text)")

    if text.count("!") > 3:
        indicators.append(f"❗ Many exclamation marks ({text.count('!')} total)")

    return indicators


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"message": "AI Phishing Email Detector API", "version": "1.0.0"}


@app.get("/health")
def health_check():
    return {"status": "healthy", "model_loaded": MODEL_LOADED}


@app.post("/predict", response_model=PredictionResponse)
def predict_email(email: EmailRequest):
    if not MODEL_LOADED:
        raise HTTPException(status_code=503, detail="Model not loaded. Check server logs.")

    try:
        full_text = email.text
        if email.subject:
            full_text = f"Subject: {email.subject}\n{full_text}"

        text_tfidf = vectorizer.transform([full_text])
        features = extract_features(full_text)
        features_sparse = csr_matrix([features])
        X_combined = hstack([text_tfidf, features_sparse])

        prediction = model.predict(X_combined)[0]
        probability = model.predict_proba(X_combined)[0]

        confidence = float(max(probability))
        is_phishing = bool(prediction == 1)
        risk_score = float(confidence * 100) if is_phishing else float((1 - confidence) * 100)

        indicators = get_indicators(full_text)

        if is_phishing:
            explanation = (
                f"⚠️ PHISHING DETECTED with {confidence:.1%} confidence. "
                "This email contains suspicious patterns commonly used in phishing attacks."
            )
        else:
            explanation = (
                f"✅ This email appears legitimate ({confidence:.1%} confidence). "
                "No significant phishing indicators detected."
            )

        return PredictionResponse(
            is_phishing=is_phishing,
            confidence=round(confidence, 4),
            risk_score=round(risk_score, 2),
            indicators=indicators,
            explanation=explanation,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/feedback")
def submit_feedback(email_text: str, correct_label: int, predicted_label: int):
    # TODO: persist feedback for model retraining
    return {"message": "Feedback received", "status": "success"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
