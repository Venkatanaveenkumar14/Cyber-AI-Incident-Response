import pandas as pd
import pickle
from data_preprocessing.ddos_preprocessor import preprocess_ddos_dataset
from data_preprocessing.feature_engineering import extract_features
from ml_model.train_model import advanced_feature_engineering

# Load your dataset (use any valid CSV you have for training or testing)
df = pd.read_csv("dataset/test_logs_1000.csv")  # or use ready_dataset.csv

# Full Preprocessing Pipeline
df, _ = preprocess_ddos_dataset(df)
df = extract_features(df)
df = advanced_feature_engineering(df)

# Drop label if present
if 'label' in df.columns:
    df = df.drop(columns=['label'])

# Save the feature column names
feature_list = df.columns.tolist()

# Save to feature_columns.pkl
with open("models/feature_columns.pkl", "wb") as f:
    pickle.dump(feature_list, f)

print(f"[DONE] feature_columns.pkl updated with {len(feature_list)} features.")