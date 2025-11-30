import pandas as pd
from ucimlrepo import fetch_ucirepo
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Fetch the dataset
print("Loading dataset...")
phiusiil_phishing_url_website = fetch_ucirepo(id=967)

# Get data as pandas dataframes
X = phiusiil_phishing_url_website.data.features
y = phiusiil_phishing_url_website.data.targets

# Combine features and target into a single DataFrame
df = pd.concat([X, y], axis=1)

# Remove rows with NaN values
df_cleaned = df.dropna()

# Find the label column
label_col = None
for col in df_cleaned.columns:
    if 'label' in col.lower() or 'target' in col.lower() or 'class' in col.lower():
        label_col = col
        break

if label_col is None and y is not None and len(y.columns) > 0:
    label_col = y.columns[0]

# Encode the Label column: 0 = 'BENIGN', 1 = 'ATTACK'
df_cleaned['Label'] = df_cleaned[label_col].map({0: 'BENIGN', 1: 'ATTACK'})

# Split into features (X) and target (y)
exclude_cols = [label_col, 'Label']
if 'FILENAME' in df_cleaned.columns:
    exclude_cols.append('FILENAME')

X = df_cleaned.drop(columns=exclude_cols)
y = df_cleaned['Label']

# Handle categorical features - use label encoding for high cardinality features
from sklearn.preprocessing import LabelEncoder

X_processed = X.copy()
label_encoders = {}

for col in X_processed.columns:
    if X_processed[col].dtype == 'object':
        # Use label encoding for categorical features
        le = LabelEncoder()
        X_processed[col] = le.fit_transform(X_processed[col].astype(str))
        label_encoders[col] = le

# Split data into train and test sets
X_train, X_test, y_train, y_test = train_test_split(X_processed, y, test_size=0.2, random_state=42, stratify=y)

# Train RandomForestClassifier
print("\nTraining RandomForestClassifier...")
rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)
rf_classifier.fit(X_train, y_train)

# Make predictions
y_pred = rf_classifier.predict(X_test)

# Evaluate with classification report
print("\nClassification Report:")
print(classification_report(y_test, y_pred))

