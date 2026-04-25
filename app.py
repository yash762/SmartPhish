from flask import Flask, render_template, request
import joblib
import re
import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime

app = Flask(__name__)

# 🔹 Load trained model
model = joblib.load("phishing_model.pkl")

# 🔹 Feature Extraction (must match training)
def extract_features(url):
    return [
        len(url),
        url.count('.'),
        url.count('/'),
        url.count('-'),
        url.count('@'),
        url.count('?'),
        url.count('%'),
        url.count('='),
        url.count('http'),
        1 if 'https' in url else 0,
        url.count('www'),
        url.count('.com'),
        url.count('.net'),
        url.count('.org')
    ]

# 🔹 Fix URL format
def fix_url(url):
    if not re.match(r'^https?://', url):
        url = 'https://' + url
    return url

# 🔹 ML Layer
def ml_layer(url):
    features = extract_features(url)
    prediction = model.predict([features])[0]
    return prediction  # 0 or 1

# 🔹 Rule-Based Layer
def rule_layer(url):
    score = 0
    url = url.lower()

    if '@' in url:
        score += 1
    if '-' in url:
        score += 1
    if len(url) > 75:
        score += 1
    if any(word in url for word in ['login', 'verify', 'secure', 'bank']):
        score += 1

    return score

# 🔹 Domain Layer
def domain_layer(url):
    score = 0

    # IP check
    if re.search(r'(\d{1,3}\.){3}\d{1,3}', url):
        score += 1

    # Suspicious TLD
    if any(tld in url for tld in ['.tk', '.ml', '.ga', '.cf']):
        score += 1

    try:
        domain = url.split("//")[-1].split("/")[0]
        socket.gethostbyname(domain)
        return score, True   # domain exists
    except:
        return score, False  # domain invalid

# 🔹 SSL Layer
def ssl_layer(url):
    score = 0
    try:
        hostname = urlparse(url).hostname
        context = ssl.create_default_context()

        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')

                if expiry < datetime.utcnow():
                    score += 1
    except:
        score += 2  # No SSL / invalid

    return score
id="brand_layer_code"

def brand_layer(url):
    score = 0
    url = url.lower()

    brands = ['paypal', 'google', 'facebook', 'amazon', 'bank']

    for brand in brands:
        # detect slight modification (paypa1, gooogle, etc.)
        if brand in url:
            score += 1
        elif brand[:-1] in url:  # simple trick
            score += 1

    return score
# 🔹 Final Decision Engine
id="final_update_code"
def final_decision(url):
    ml = ml_layer(url)
    rule = rule_layer(url)
    domain_score, is_valid = domain_layer(url)
    ssl = ssl_layer(url)

    total = ml + rule + domain_score + ssl

    # ✅ Step 1: Strong phishing check FIRST
    if total >= 4:
        return "⚠️ Phishing Website Detected", ml, rule, domain_score, ssl

    # 🚫 Step 2: Only if low score, then check invalid
    if not is_valid:
        return "🚫 Invalid or May Be Suspicious Website", ml, rule, domain_score, ssl

    # ✅ Step 3: Legitimate
    return "✅ Legitimate Website", ml, rule, domain_score, ssl
def model_predict(url):
    return final_decision(url)

# 🔹 Home Page
@app.route('/')
def home():
    return render_template('index.html')

# 🔹 Prediction Route
@app.route('/predict', methods=['POST'])
def predict():
    try:
        url = request.form['url']
        fixed_url = fix_url(url)

        result, ml, rule, domain, ssl = model_predict(fixed_url)

        return render_template('index.html',
                               prediction_text=result,
                               checked_url=fixed_url,
                               ml_score=ml,
                               rule_score=rule,
                               domain_score=domain,
                               ssl_score=ssl)

    except Exception as e:
        return render_template('index.html',
                               prediction_text="Error: " + str(e))

# 🔹 Run App
if __name__ == "__main__":
    app.run(debug=True)