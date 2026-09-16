import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix
import joblib


# -----------------------------
# SAMPLE DATASET
# -----------------------------
data = {
    "url_length": [
        20, 25, 30, 80, 90, 100, 45, 60,
        120, 35, 70, 110, 40, 95, 55, 130
    ],

    "has_at": [
        0, 0, 0, 1, 1, 1, 0, 0,
        1, 0, 1, 1, 0, 1, 0, 1
    ],

    "has_hyphen": [
        0, 0, 1, 1, 1, 1, 0, 1,
        1, 0, 1, 1, 0, 1, 0, 1
    ],

    "suspicious_words": [
        0, 0, 1, 3, 4, 5, 1, 2,
        5, 0, 3, 5, 1, 4, 2, 5
    ],

    "has_ip": [
        0, 0, 0, 1, 1, 1, 0, 0,
        1, 0, 1, 1, 0, 1, 0, 1
    ],

    "https": [
        1, 1, 1, 0, 0, 0, 1, 1,
        0, 1, 0, 0, 1, 0, 1, 0
    ],

    "label": [
        0, 0, 0, 2, 2, 2, 0, 1,
        2, 0, 1, 2, 0, 2, 1, 2
    ]
}


# Create DataFrame
df = pd.DataFrame(data)

X = df.drop("label", axis=1)
y = df["label"]


# Train Random Forest
model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X, y)


# Prediction
predictions = model.predict(X)


# Calculate Accuracy
accuracy = accuracy_score(y, predictions) * 100


# Confusion Matrix
cm = confusion_matrix(y, predictions)


# Save Model
joblib.dump(model, "phishing_model.pkl")


print("\n🤖 AI Model Trained Successfully!")
print("📁 Model saved as: phishing_model.pkl")
print(f"📊 Model Accuracy: {accuracy:.2f}%")

print("\n📈 Confusion Matrix:")
print(cm)