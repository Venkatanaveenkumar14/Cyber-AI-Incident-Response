
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from sklearn.metrics import roc_curve, auc
from sklearn.preprocessing import LabelBinarizer
from ml_model.model_predictor import ModelManager

# Load Sample Data
print("[INFO] Loading a small stratified sample from the full dataset")
df = pd.read_csv("dataset/ready_dataset.csv")
df.columns = df.columns.str.strip()

if 'Label' not in df.columns:
    raise ValueError("Missing 'Label' column in dataset.")

df.rename(columns={'Label': 'label'}, inplace=True)

# Sample with stratification
df_sampled = df.groupby("label", group_keys=False).apply(lambda x: x.sample(min(len(x), 500)))
df_sampled.reset_index(drop=True, inplace=True)

# Predict using ModelManager
print("[INFO] Running model inference for ROC curve")
preds, probs = ModelManager.predict(df_sampled)  # Pass full DataFrame with label
probs = np.array(probs)  # Convert to NumPy array for slicing

# Separate y after prediction
y = df_sampled['label']

# Binarize True Labels
lb = LabelBinarizer()
y_bin = lb.fit_transform(y)
class_names = lb.classes_

# Plot ROC
print("[INFO] Plotting ROC curves")
plt.figure(figsize=(10, 8))
for i in range(len(class_names)):
    fpr, tpr, _ = roc_curve(y_bin[:, i], probs[:, i])
    roc_auc = auc(fpr, tpr)
    plt.plot(fpr, tpr, label=f"{class_names[i]} (AUC = {roc_auc:.2f})")

plt.plot([0, 1], [0, 1], "k--")
plt.xlabel("False Positive Rate")
plt.ylabel("True Positive Rate")
plt.title("Receiver Operating Characteristic (ROC) Curves")
plt.legend(loc="lower right")
plt.grid(True)
plt.tight_layout()
plt.savefig("roc_curves.png")
plt.show()