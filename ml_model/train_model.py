import sys
import traceback

def handle_exception(exc_type, exc_value, exc_traceback):
    traceback.print_exception(exc_type, exc_value, exc_traceback)
    sys.exit(1)

sys.excepthook = handle_exception


# Imports
import os
import pickle
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# CatBoost and XGBoost
from catboost import CatBoostClassifier
import xgboost as xgb

# Sklearn & Imbalanced-Learn
from sklearn.model_selection import train_test_split, RandomizedSearchCV, StratifiedKFold
from sklearn.metrics import (accuracy_score, classification_report, 
                             confusion_matrix, roc_auc_score)
from sklearn.utils.class_weight import compute_class_weight
from imblearn.combine import SMOTEENN

# For random search distributions
import scipy.stats as st

# Adding Project Root Path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(project_root)


# Custom Modules
from data_preprocessing.ddos_preprocessor import preprocess_ddos_dataset
from data_preprocessing.feature_engineering import extract_features


# Additional Feature Engineering (Domain Specific Placeholder according to CIC-DDoS2019 & CICIDS2017)

def advanced_feature_engineering(df: pd.DataFrame) -> pd.DataFrame:

    #Creates features proven effective for CIC-DDoS2019/CICIDS2017 detection.
    #Targets protocol-agnostic patterns seen in UDP floods, SYN floods, and brute-force attacks.

    df = df.copy()  # Avoid pandas chained assignment warnings

    # 1. Amplification Attack Ratio (DNS/NTP)
    if all(col in df.columns for col in ['total_length_of_bwd_packets', 'total_length_of_fwd_packets']):
        df['amplification_ratio'] = (
            df['total_length_of_bwd_packets'] / 
            (df['total_length_of_fwd_packets'] + 1e-6)
        )

    # 2. SYN Flood Signature (SYN)
    if all(col in df.columns for col in ['syn_flag_count', 'ack_flag_count']):
        df['syn_ack_discrepancy'] = (
            df['syn_flag_count'] - df['ack_flag_count']
        ) / (df['syn_flag_count'] + df['ack_flag_count'] + 1e-6)

    # 3. UDP Fragmentation Detection (UDP)
    if 'fwd_packets/s' in df.columns and 'total_fwd_packets' in df.columns and 'flow_duration' in df.columns:
        df['udp_frag_heuristic'] = (
            df['fwd_packets/s'] * df['total_fwd_packets']
        ) / (df['flow_duration'] + 1e-6)

    # 4. Brute-Force RST Rate (Br-F)
    if 'rst_flag_count' in df.columns and 'flow_duration' in df.columns:
        df['rst_per_sec'] = df['rst_flag_count'] / (df['flow_duration'] + 1e-6)

    # 5. Burstiness Index (B)
    if 'flow_iat_std' in df.columns and 'flow_iat_mean' in df.columns:
        df['burstiness'] = (
            df['flow_iat_std'] / (df['flow_iat_mean'] + 1e-6)
        )
        df['burstiness'] = df['burstiness'].replace([np.inf, -np.inf], 0)

    # 6. Malicious Subflow Pattern (Mal SfP)
    if all(col in df.columns for col in ['subflow_fwd_packets', 'subflow_bwd_packets']):
        df['subflow_imbalance'] = (
            df['subflow_fwd_packets'] - df['subflow_bwd_packets']
        ) / (df['subflow_fwd_packets'] + df['subflow_bwd_packets'] + 1e-6)

    # 7. Small Payload Flood (Payl)
    if all(col in df.columns for col in ['fwd_header_length', 'total_length_of_fwd_packets']):
        df['small_payload_ratio'] = (
            df['fwd_header_length'] / (df['total_length_of_fwd_packets'] + 1e-6)
        )

    # 8. Flow Completion Heuristic (FCH)
    if 'fin_flag_count' in df.columns and 'flow_packets/s' in df.columns:
        df['premature_fin'] = (
            df['fin_flag_count'] * (1 / (df['flow_packets/s'] + 1e-6))
        )

    return df

# Main Script
if __name__ == "__main__":
    # 1. Load Dataset
    df = pd.read_csv("dataset/ready_dataset.csv", 
                     dtype=str, sep=',')
    print("Initial Data Shape:", df.shape)

    # 2. Preprocessing
    df, label_encoder = preprocess_ddos_dataset(df)
    df = extract_features(df)
    print("Data Shape after Basic Preprocessing:", df.shape)

    # 3. Additional Feature Engineering
    df = advanced_feature_engineering(df)
    print("Data Shape after Advanced Feature Engineering:", df.shape)

    # 4. Optional: Sampling for Runtime
    MAX_ROWS = 1_000_000
    if len(df) > MAX_ROWS:
        df = df.sample(n=MAX_ROWS, random_state=42)
        print(f"Sampled dataset to {MAX_ROWS} rows for training.")

    # 5. Prepare Data
    X = df.drop(columns=['label'])
    y = df['label'].astype(int)
    print("Final Feature Columns Shape:", X.shape)
    print("Label Distribution:\n", y.value_counts())

    # Train-test split with stratification
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    print("Training Data Shape:", X_train.shape)
    print("Testing Data Shape:", X_test.shape)

    # Identify categorical columns (if any)
    categorical_features = X_train.select_dtypes(include=['object']).columns.tolist()
    print("Categorical Features:", categorical_features)

    # Check for NaNs
    print("NaN count in Training Features:", X_train.isna().sum().sum())

    # 6. SMOTEENN Oversampling
    print("Before SMOTEENN class distribution:\n", y_train.value_counts())
    sm = SMOTEENN(random_state=42)
    X_train_res, y_train_res = sm.fit_resample(X_train, y_train)
    print("After SMOTEENN class distribution:\n", y_train_res.value_counts())

    # Optional: compute class weights (not used here, since data is balanced now)
    class_weights = compute_class_weight(
        class_weight='balanced',
        classes=np.unique(y_train_res),
        y=y_train_res
    )
    class_weights_dict = dict(enumerate(class_weights))
    print("Computed Class Weights:", class_weights_dict)

    # 7. Hyperparameter Tuning for Each Model
    cv_folds = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    n_iter_search = 20  # Can increase with resources/time allow

    # 7.1 CatBoost
    catboost_param_dist = {
        'depth': [6, 8, 10, 12],
        'learning_rate': [0.01, 0.03, 0.05, 0.1],
        'l2_leaf_reg': [1, 3, 5, 7],
        'iterations': [200, 300, 500, 700]
    }
    cat_model = CatBoostClassifier(
        task_type='GPU',
        devices='0',
        random_seed=42,
        loss_function='MultiClass',
        eval_metric='MultiClass',
        verbose=0
    )
    # 7.2 XGBoost (First Variant)
    xgb_model = xgb.XGBClassifier(
        tree_method='gpu_hist',  # GPU acceleration
        predictor='gpu_predictor',
        use_label_encoder=False,
        eval_metric='mlogloss',
        random_state=42
    )
    xgb_param_dist = {
        'max_depth': [6, 8, 10, 12],
        'learning_rate': [0.01, 0.03, 0.05, 0.1],
        'n_estimators': [200, 300, 500, 700],
        'subsample': [0.8, 1.0],
        'colsample_bytree': [0.8, 1.0]
    }

    # 7.3 XGBoost (Second Variant for Ensemble Diversity)
    xgb_model_variant = xgb.XGBClassifier(
        tree_method='gpu_hist', 
        predictor='gpu_predictor',
        use_label_encoder=False,
        eval_metric='mlogloss',
        random_state=42
    )
    xgb_variant_param_dist = {
        'max_depth': [4, 6, 8, 10],
        'learning_rate': [0.005, 0.01, 0.03, 0.05],
        'n_estimators': [300, 500, 700, 1000],
        'subsample': [0.7, 0.8, 0.9, 1.0],
        'colsample_bytree': [0.7, 0.8, 0.9, 1.0],
        'gamma': [0, 0.1, 0.2, 0.3]
    }

    def tune_model(model, param_dist, X_res, y_res, cat_features=None):
        from catboost import CatBoostClassifier
        search = RandomizedSearchCV(
            estimator=model,
            param_distributions=param_dist,
            n_iter=n_iter_search,
            scoring=['accuracy', 'f1_weighted'],
            refit='accuracy',
            cv=cv_folds,
            verbose=1,
            n_jobs=1  # GPU training typically can't be parallelized at sklearn level
        )
        # Pass cat_features only if the model is CatBoostClassifier
        if cat_features is not None and isinstance(model, CatBoostClassifier):
            search.fit(X_res, y_res, cat_features=cat_features)
        else:
            search.fit(X_res, y_res)
        return search

    print("\n--- Tuning CatBoost ---")
    catboost_search = tune_model(cat_model, catboost_param_dist, X_train_res, y_train_res,
                                 cat_features=categorical_features if categorical_features else None)
    best_catboost = catboost_search.best_estimator_
    print(f"\nBest CatBoost Params: {catboost_search.best_params_}")
    print(f"BEST CatBoost CV Accuracy: {catboost_search.best_score_:.4f}")

    print("\n--- Tuning XGBoost (First Variant) ---")
    xgb_search = tune_model(xgb_model, xgb_param_dist, X_train_res, y_train_res)
    best_xgb = xgb_search.best_estimator_
    print(f"\nBest XGBoost Params: {xgb_search.best_params_}")
    print(f"BEST XGBoost CV Accuracy: {xgb_search.best_score_:.4f}")

    print("\n--- Tuning XGBoost (Second Variant) ---")
    xgb_variant_search = tune_model(xgb_model_variant, xgb_variant_param_dist, X_train_res, y_train_res)
    best_xgb_variant = xgb_variant_search.best_estimator_
    print(f"\nBest XGBoost Variant Params: {xgb_variant_search.best_params_}")
    print(f"BEST XGBoost Variant CV Accuracy: {xgb_variant_search.best_score_:.4f}")

    # 8. Evaluate Each Best Model on Test Set
    def evaluate_model(model, model_name, X_t, y_t):
        y_pred = model.predict(X_t)
        accuracy = accuracy_score(y_t, y_pred)
        print(f"\n=== {model_name} Test Accuracy: {accuracy:.4f}")
        print(f"[DEBUG] {model_name} - y_test size: {len(y_t)}, y_pred size: {len(y_pred)}")
        try:
            roc_score = roc_auc_score(y_t, model.predict_proba(X_t), multi_class='ovr')
            print(f"{model_name} ROC-AUC Score: {roc_score:.4f}")
        except Exception as e:
            print(f"{model_name} ROC-AUC calculation not possible: {e}")

        print(f"{model_name} Classification Report:\n", classification_report(y_t, y_pred))
        conf_matrix = confusion_matrix(y_t, y_pred)
        plt.figure(figsize=(8,6))
        sns.heatmap(conf_matrix, annot=True, fmt='d', cmap='Blues')
        plt.xlabel("Predicted")
        plt.ylabel("Actual")
        plt.title(f"Confusion Matrix - {model_name}")
        plt.savefig(f"models/conf_matrix_{model_name}.png")
        plt.close()

    evaluate_model(best_catboost, "CatBoost", X_test, y_test)
    evaluate_model(best_xgb, "XGBoost", X_test, y_test)
    evaluate_model(best_xgb_variant, "XGBoost_Variant", X_test, y_test)

    # 9. Stacking Ensemble
    from sklearn.ensemble import StackingClassifier

    final_meta_learner = CatBoostClassifier(
        task_type='GPU',
        devices='0',
        random_seed=42,
        loss_function='MultiClass',
        eval_metric='MultiClass',
        verbose=0
    )

    estimators = [
        ('catboost', best_catboost),
        ('xgboost1', best_xgb),
        ('xgboost2', best_xgb_variant)
    ]
    stacking_clf = StackingClassifier(
        estimators=estimators,
        final_estimator=final_meta_learner,
        cv=5,
        n_jobs=1
    )

    print("\n--- Training Stacking Ensemble ---")
    stacking_clf.fit(X_train_res, y_train_res)
    print("Stacking Ensemble training completed.")

    evaluate_model(stacking_clf, "StackingEnsemble", X_test, y_test)

    # 10. Save All Best Models
    print("\n--- Saving Models ---")
    best_catboost.save_model('models/best_catboost_model_stkxgb.cbm')
    with open('models/best_xgb_model.pkl', 'wb') as f:
        pickle.dump(best_xgb, f)
    with open('models/best_xgb_variant_model.pkl', 'wb') as f:
        pickle.dump(best_xgb_variant, f)
    with open('models/stacking_ensemble.pkl', 'wb') as f:
        pickle.dump(stacking_clf, f)

    print("All models have been saved successfully.")
    print("\nAll done!")