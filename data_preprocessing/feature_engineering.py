#data_preprocessing/feature_engineering.py
import numpy as np
import pandas as pd
from sklearn.ensemble import ExtraTreesClassifier
import logging
import os

logger = logging.getLogger(__name__)

# Constants
CORRELATION_THRESHOLD = float(os.environ.get('CORRELATION_THRESHOLD', 0.95))
TOP_K_FEATURES = int(os.environ.get('TOP_K_FEATURES', 50))

def remove_highly_correlated_features(df, label_col='label'):

    #Removes highly correlated features.

    try:
        logger.info("Starting feature correlation removal...")
        threshold = float(os.environ.get('CORRELATION_THRESHOLD', CORRELATION_THRESHOLD))
        numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
        if label_col in numeric_cols:
            numeric_cols.remove(label_col)

        corr_matrix = df[numeric_cols].corr().abs()
        upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))

        dropped_features = [column for column in upper.columns if any(upper[column] > threshold)]
        df_reduced = df.drop(columns=dropped_features)

        logger.info(f"Removed highly correlated features (threshold={threshold}): {dropped_features}")
        return df_reduced, dropped_features

    except Exception as e:
        logger.exception("Error removing correlated features.")
        return df, []

def select_top_features_by_importance(df, label_col='label'):

    #Selects top features by importance.

    try:
        logger.info("Starting feature selection by importance...")
        top_k = int(os.environ.get('TOP_K_FEATURES', TOP_K_FEATURES))
        X = df.drop(columns=[label_col])
        y = df[label_col]

        model = ExtraTreesClassifier(n_estimators=50, random_state=42, n_jobs=-1)
        model.fit(X, y)

        importances = model.feature_importances_
        importance_df = pd.DataFrame({
            'feature': X.columns,
            'importance': importances
        }).sort_values(by='importance', ascending=False)

        top_features = importance_df.head(top_k)['feature'].tolist()
        df_selected = df[top_features + [label_col]]

        logger.info(f"Selected top {top_k} features: {top_features}")
        return df_selected, top_features

    except Exception as e:
        logger.exception("Error selecting top features.")
        return df, []

def extract_features(df: pd.DataFrame, drop_high_corr: bool = True):

    #Extracts and optimizes features.

    try:
        logger.info("Starting feature extraction and optimization...")

        if 'label' not in df.columns:
            logger.error("'label' column missing before feature extraction!")
            return df

        feature_cols = [col for col in df.columns if col != 'label']
        for col in feature_cols:
            df[col] = pd.to_numeric(df[col], errors='coerce')
        logger.debug("Converted feature columns to numeric.")

        df.fillna(0, inplace=True)
        logger.debug("Filled missing values.")

        if drop_high_corr:
            df, dropped_corr = remove_highly_correlated_features(df, label_col='label')
            logger.info(f"Features dropped due to high correlation: {dropped_corr}")
        else:
            dropped_corr = []
            logger.info("Skipped removing highly correlated features.")

        top_k = int(os.environ.get('TOP_K_FEATURES', TOP_K_FEATURES))
        if len(df.columns) - 1 > top_k:
            # df, top_features = select_top_features_by_importance(df, label_col='label', top_k=top_k) #Done it for ROC checking
            df, top_features = select_top_features_by_importance(df, label_col='label')
            logger.info(f"Top features selected by importance: {top_features}")
        else:
            logger.info("Number of features is small; skipping feature selection.")

        logger.info(f"Feature extraction and optimization completed! Final shape: {df.shape}")
        return df

    except Exception as e:
        logger.exception("Error during feature extraction.")
        return df