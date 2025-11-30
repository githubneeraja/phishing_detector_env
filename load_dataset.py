import pandas as pd
from ucimlrepo import fetch_ucirepo

# Fetch the dataset
print("Downloading PhiUSIIL Phishing URL Dataset...")
phiusiil_phishing_url_website = fetch_ucirepo(id=967)

# Get data as pandas dataframes
X = phiusiil_phishing_url_website.data.features
y = phiusiil_phishing_url_website.data.targets

# Combine features and target into a single DataFrame
df = pd.concat([X, y], axis=1)

print(f"Dataset loaded. Shape: {df.shape}")
print(f"Columns: {df.columns.tolist()}")

# Check for missing values
print(f"\nMissing values before handling:")
print(df.isnull().sum().sum())

# Remove rows with NaN values
df_cleaned = df.dropna()

print(f"\nRows removed: {len(df) - len(df_cleaned)}")
print(f"Dataset shape after removing NaN: {df_cleaned.shape}")

# Find the label column (it might be named differently)
label_col = None
for col in df_cleaned.columns:
    if 'label' in col.lower() or 'target' in col.lower() or 'class' in col.lower():
        label_col = col
        break

if label_col is None:
    # If no label column found, check the last column or columns that might be targets
    print("\nAvailable columns:", df_cleaned.columns.tolist())
    # The target might be in the y dataframe, let's check
    if y is not None and len(y.columns) > 0:
        label_col = y.columns[0]
        print(f"Using target column: {label_col}")

if label_col is None:
    raise ValueError("Could not find label column in the dataset")

print(f"\nLabel column found: {label_col}")
print(f"Label value counts before encoding:")
print(df_cleaned[label_col].value_counts())

# Encode the Label column: 0 = 'BENIGN', 1 = 'ATTACK'
df_cleaned['Label'] = df_cleaned[label_col].map({0: 'BENIGN', 1: 'ATTACK'})

print(f"\nLabel value counts after encoding:")
print(df_cleaned['Label'].value_counts())

# Split into features (X) and target (y)
# Exclude the original label column and the new Label column, plus FILENAME if it exists
exclude_cols = [label_col, 'Label']
if 'FILENAME' in df_cleaned.columns:
    exclude_cols.append('FILENAME')

X = df_cleaned.drop(columns=exclude_cols)
y = df_cleaned['Label']

print(f"\nFeatures (X) shape: {X.shape}")
print(f"Target (y) shape: {y.shape}")
print(f"\nFeature columns: {X.columns.tolist()}")
print(f"\nTask completed successfully!")

