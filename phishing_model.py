import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import joblib

# Load enhanced dataset
df = pd.read_csv("phishing_data.csv")

# Features & Label
X = df.drop("Result", axis=1)
y = df["Result"]

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Report
print(classification_report(y_test, model.predict(X_test)))

# Save model
joblib.dump(model, "phishing_model.pkl")
print("✅ Model saved as phishing_model.pkl")
