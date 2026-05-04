import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Column names for NSL-KDD dataset
columns = [
    'duration', 'protocol_type', 'service', 'flag',
    'src_bytes', 'dst_bytes', 'land', 'wrong_fragment',
    'urgent', 'hot', 'num_failed_logins', 'logged_in',
    'num_compromised', 'root_shell', 'su_attempted',
    'num_root', 'num_file_creations', 'num_shells',
    'num_access_files', 'num_outbound_cmds', 'is_host_login',
    'is_guest_login', 'count', 'srv_count', 'serror_rate',
    'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate',
    'same_srv_rate', 'diff_srv_rate', 'srv_diff_host_rate',
    'dst_host_count', 'dst_host_srv_count',
    'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
    'dst_host_serror_rate', 'dst_host_srv_serror_rate',
    'dst_host_rerror_rate', 'dst_host_srv_rerror_rate',
    'label', 'difficulty'
]

print("Loading dataset...")
train = pd.read_csv('data/KDDTrain+.txt', names=columns)
test = pd.read_csv('data/KDDTest+.txt', names=columns)

# Drop difficulty column
train = train.drop('difficulty', axis=1)
test = test.drop('difficulty', axis=1)

# Convert labels to binary: normal vs attack
train['label'] = train['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')
test['label'] = test['label'].apply(lambda x: 'normal' if x == 'normal' else 'attack')

print(f"Training samples: {len(train)}")
print(f"Test samples: {len(test)}")
print(f"\nLabel distribution:\n{train['label'].value_counts()}")

# Encode categorical columns
encoders = {}
for col in ['protocol_type', 'service', 'flag']:
    le = LabelEncoder()
    train[col] = le.fit_transform(train[col])
    test[col] = le.transform(test[col])
    encoders[col] = le

# Split features and labels
X_train = train.drop('label', axis=1)
y_train = train['label']
X_test = test.drop('label', axis=1)
y_test = test['label']

# Train the model
print("\nTraining Random Forest model...")
model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
model.fit(X_train, y_train)

# Evaluate
print("\nEvaluating model...")
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"\nAccuracy: {accuracy * 100:.2f}%")
print("\nDetailed Report:")
print(classification_report(y_test, y_pred))

# Save the model and encoders
print("\nSaving model...")
joblib.dump(model, 'models/ids_model.pkl')
joblib.dump(encoders, 'models/encoders.pkl')
print("Model saved to models/ids_model.pkl")
print("Encoders saved to models/encoders.pkl")
print("\nPhase 3 complete!")