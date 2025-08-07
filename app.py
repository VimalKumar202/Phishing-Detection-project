import streamlit as st
import joblib
import pandas as pd
import re
import requests
import whois
from urllib.parse import urlparse
from datetime import datetime

# Load trained model
model = joblib.load("phishing_model.pkl")

# Streamlit UI
st.title("🔒 AI-Based Phishing URL Detection")
st.markdown("Enter a full URL below. The system will extract features and detect if it's **Phishing** or **Legitimate**.")

# User input
url = st.text_input("🌐 Enter the URL to check")

# Feature extraction function
def extract_features(url):
    features = {}

    features['URL_Length'] = len(url)
    features['Has_At'] = 1 if '@' in url else 0
    features['HTTPS'] = 1 if url.startswith("https") else 0

    domain = urlparse(url).netloc
    features['Subdomain_Count'] = domain.count('.') - 1

    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    features['Has_IP'] = 1 if re.search(ip_pattern, url) else 0

    suspicious_words = ['login', 'secure', 'bank', 'update', 'verify']
    features['Has_Suspicious_Words'] = 1 if any(word in url.lower() for word in suspicious_words) else 0

    try:
        response = requests.get(url, timeout=5)
        features['Redirect_Count'] = len(response.history)
    except:
        features['Redirect_Count'] = -1

    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        features['Domain_Age_Days'] = (datetime.now() - creation_date).days
    except:
        features['Domain_Age_Days'] = -1

    features['HTTPS_Token_In_Domain'] = 1 if 'https' in domain.lower() else 0

    return features

# Prediction logic
if st.button("🔍 Check URL"):
    if url:
        try:
            input_features = extract_features(url)
            df = pd.DataFrame([input_features])
            prediction = model.predict(df)
            result = "🚨 Phishing Site" if prediction[0] == 1 else "✅ Legitimate Site"
            st.success(f"Result: {result}")
            st.subheader("🔍 Extracted Features")
            st.json(input_features)
        except Exception as e:
            st.error(f"Error during processing: {e}")
    else:
        st.warning("Please enter a valid URL.")
