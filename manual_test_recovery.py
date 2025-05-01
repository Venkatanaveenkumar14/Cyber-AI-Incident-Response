# To recover the labels if forgot label mapping
import sy
import os
import numpy as np
import pandas as pd

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), ".")))

from ml_model.model_predictor import ModelManager
from ml_model.class_mapping_utils import get_class_label

print(f"[DEBUG] sys.path updated. Current working directory: {os.getcwd()}")

# Load fixed CSV
df = pd.read_csv("<username>/<drive>/Automated_Incident_Response/recovery.csv")

# Predict
preds, probs = ModelManager.predict(df)

# Display recovered labels
for i, pred in enumerate(preds):
    # Safely flatten prediction
    if isinstance(pred, (np.ndarray, list)):
        pred = int(pred[0])
    else:
        pred = int(pred)

    pred_label = get_class_label(pred)
    print(f"Predicted Class: {pred} ({pred_label})")