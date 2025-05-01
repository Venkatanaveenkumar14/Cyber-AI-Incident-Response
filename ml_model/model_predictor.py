# ml_model/model_predictor.py

import os
import pandas as pd
import numpy as np
from catboost import CatBoostClassifier
import logging

from data_preprocessing.ddos_preprocessor import preprocess_ddos_dataset
from data_preprocessing.feature_engineering import extract_features
from ml_model.feature_generator import advanced_feature_engineering

logger = logging.getLogger(__name__)

class ModelManager:
    _catboost_model = None
    _feature_order = None

    MODEL_DIR = os.environ.get('MODEL_DIR', 'models')

    @classmethod
    def load_models(cls):
        if cls._catboost_model is None:
            cat_path = os.path.join(cls.MODEL_DIR, "retrained_best_catboost_model_stkxgb.cbm")
            cls._catboost_model = CatBoostClassifier()
            cls._catboost_model.load_model(cat_path)
            cls._catboost_model.n_classes_ = 14
            logger.info(f"[ModelManager] Loaded CatBoost model from {cat_path}")

        if cls._feature_order is None:
            feature_order_path = os.path.join(cls.MODEL_DIR, "retrained_feature_columns.pkl")
            import pickle
            with open(feature_order_path, "rb") as f:
                cls._feature_order = pickle.load(f)
            logger.info(f"[ModelManager] Loaded feature order from {feature_order_path}")

    @classmethod
    def predict(cls, df: pd.DataFrame, batch_size=1000):
        cls.load_models()
        df = df.copy()

        # Preprocessing
        df, _ = preprocess_ddos_dataset(df)
        if df is None:
            raise ValueError("Data preprocessing failed.")
        df = extract_features(df)
        df = advanced_feature_engineering(df)

        missing = set(cls._feature_order) - set(df.columns)
        for feature in missing:
            df[feature] = 0.0
        df = df[cls._feature_order]

        X = df.values

        preds, probs = [], []
        for i in range(0, len(X), batch_size):
            batch = X[i:i+batch_size]
            preds.extend(cls._catboost_model.predict(batch))
            probs.extend(cls._catboost_model.predict_proba(batch))

        return preds, probs

