import pandas as pd
import pickle
from catboost import CatBoostClassifier, Pool

# Load dataset
df = pd.read_csv("<username>/<drive>/Automated_Incident_Response/dataset/ready_dataset.csv")

# Separate features and label
X = df.drop(columns=["label"])
y = df["label"]

# Fit CatBoost briefly (fast training for feature selection)
model = CatBoostClassifier(verbose=0, random_seed=42)
model.fit(X, y)

# Get feature importances
importances = model.get_feature_importance(Pool(X, y))
feature_scores = pd.DataFrame({
    "Feature": X.columns,
    "Importance": importances
}).sort_values(by="Importance", ascending=False)

# Select Top 15 features
top_features = feature_scores.head(15)["Feature"].tolist()

# Save the reduced dataset
df_reduced = df[top_features + ["label"]]
df_reduced.to_csv("dataset/ready_dataset_top15.csv", index=False)

# Save for production use in model_predictor
with open("models/feature_columns.pkl", "wb") as f:
    pickle.dump(top_features, f)

print("[DONE] Top 15 features selected and saved:")
print(feature_scores.head(15))

