import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# 1. Load data
df = pd.read_csv('dataset.csv')

# 2. Split data into Features (X) and Target (y)
X = df.drop(['Result'], axis=1) # All columns except Result
y = df['Result'] # Only the Result column

# 3. Split into Training (80%) and Testing (20%)
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# 4. Initialize and Train the Model (Random Forest)
print("Training the AI model... Please wait.")
model = RandomForestClassifier(n_estimators=100)
model.fit(X_train, y_train)

# 5. Check Accuracy
predictions = model.predict(X_test)
accuracy = accuracy_score(y_test, predictions)

print(f"✅ Training Complete!")
print(f"🎯 Model Accuracy: {accuracy * 100:.2f}%")

# 6. Save the model to a file
joblib.dump(model, 'phishing_model.pkl')
print("💾 Model saved as 'phishing_model.pkl'")