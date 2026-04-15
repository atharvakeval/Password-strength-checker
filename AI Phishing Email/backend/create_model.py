import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import os

# Create models directory if not exists
os.makedirs('models', exist_ok=True)

# Sample training data
phishing_emails = [
    "URGENT: Your account has been compromised. Click here immediately to verify your identity: http://suspicious-link.com",
    "Dear Customer, We noticed unusual activity. Please confirm your password at: http://fake-bank.com/login",
    "CONGRATULATIONS! You've won $1,000,000! Claim now at: http://lottery-scam.com",
    "Security Alert: Your PayPal account is limited. Restore access: http://paypal-fake.com/verify",
    "Action Required: Your Netflix subscription expires today. Update payment: http://netflix-fake.com",
    "Verify your email immediately or your account will be deleted within 24 hours!",
    "You have 1 new voicemail. Listen here: http://voicemail-scam.com",
    "Invoice #9876 attached. Please review and pay: http://invoice-scam.com/pay",
    "Your password expires today. Change it here: http://password-expired-fake.com",
    "URGENT: Bank account suspended. Click to reactivate: http://bank-suspended.com"
]

legit_emails = [
    "Hi team, Please review the attached quarterly report. Let me know if you have questions.",
    "Meeting rescheduled to 3 PM tomorrow. Conference room B.",
    "Thanks for your order! Your package will arrive Friday.",
    "Don't forget about the team lunch this Friday at noon.",
    "Project update: Development is on track for the deadline.",
    "Can you send me the latest version of the presentation?",
    "Happy birthday! Hope you have a great day.",
    "Reminder: Dentist appointment tomorrow at 2 PM.",
    "The report has been approved. Great work everyone!",
    "Please find the minutes from yesterday's meeting attached."
]

# Combine data
all_emails = phishing_emails + legit_emails
labels = [1] * len(phishing_emails) + [0] * len(legit_emails)  # 1=phishing, 0=legit

# Create and fit TF-IDF vectorizer
vectorizer = TfidfVectorizer(max_features=100, ngram_range=(1, 2), stop_words='english')
X_tfidf = vectorizer.fit_transform(all_emails)

# Simple feature engineering function
def extract_features(text):
    text_lower = text.lower()
    features = [
        len(text),  # text_length
        len(text.split()),  # num_words
        text.count('!'),  # num_exclamation
        sum(1 for c in text if c.isupper()),  # num_capitals
        sum(1 for c in text if c.isupper()) / len(text) if text else 0,  # capital_ratio
        sum(1 for word in ['urgent', 'immediately', 'alert', 'warning', 'suspended', 'verify', 'confirm', 'action required', 'expires'] if word in text_lower),  # urgency_score
        sum(1 for word in ['password', 'credit card', 'bank', 'account', 'login', 'ssn', 'payment', 'invoice'] if word in text_lower),  # financial_score
        1 if 'http' in text_lower else 0,  # has_url
        len([w for w in text_lower.split() if 'http' in w]),  # num_urls
        1 if any(kw in text_lower for kw in ['verify', 'secure', 'account', 'login', 'update', 'confirm']) else 0,  # suspicious_domains
        0,  # ip_in_url (simplified)
        0,  # short_urls (simplified)
        0,  # num_spelling_errors (simplified)
        0,  # has_html
        0   # has_script
    ]
    return features

# Extract features for all emails
feature_list = [extract_features(email) for email in all_emails]

# Combine TF-IDF + engineered features
from scipy.sparse import hstack, csr_matrix
X_combined = hstack([X_tfidf, csr_matrix(feature_list)])

# Train model
model = RandomForestClassifier(n_estimators=50, random_state=42)
model.fit(X_combined, labels)

# Save everything
joblib.dump(model, 'models/phishing_detector_model.pkl')
joblib.dump(vectorizer, 'models/tfidf_vectorizer.pkl')
joblib.dump(['text_length', 'num_words', 'num_exclamation', 'num_capitals', 'capital_ratio',
             'urgency_score', 'financial_score', 'has_url', 'num_urls', 'suspicious_domains',
             'ip_in_url', 'short_urls', 'num_spelling_errors', 'has_html', 'has_script'], 
            'models/feature_columns.pkl')

print("✅ Model created successfully!")
print(f"📊 Training samples: {len(all_emails)}")
print(f"🎯 Accuracy on training: {model.score(X_combined, labels):.2%}")