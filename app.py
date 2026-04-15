from flask import Flask, render_template, request
import numpy as np
import joblib
import pandas as pd

app = Flask(__name__)

# Load trained model
model = joblib.load("phishing_model.pkl")
scaler = joblib.load("scaler.pkl")

# Load dataset column structure (important!)
data = pd.read_csv("PhiUSIIL_Phishing_URL_Dataset.csv")
data = data.drop(columns=["FILENAME", "URL", "Domain", "TLD", "Title"],errors='ignore')  # Drop non-feature columns
feature_columns = data.drop("label", axis=1).columns


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/predict", methods=["POST"])
def predict():
    user_input = request.form["url"]

    # Create empty feature vector
    input_features = np.zeros(len(feature_columns))

    # Basic example features (you can improve this)
    input_features[0] = len(user_input)
    input_features[1] = user_input.count('.')
    input_features[2] = 1 if "https" in user_input else 0
    input_features[3] = 1 if "@" in user_input else 0

    input_features = scaler.transform([input_features])
    prediction = model.predict(input_features)

    result = "Legitimate Website" if prediction[0] == 1 else "Phishing Website"

    return render_template("index.html", prediction_text=result)


if __name__ == "__main__":
    app.run(debug=False)

