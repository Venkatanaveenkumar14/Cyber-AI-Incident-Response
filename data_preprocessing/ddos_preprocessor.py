#data_preprocessing/ddos_preprocessor.py
import pandas as pd
from sklearn.preprocessing import LabelEncoder, StandardScaler
import numpy as np
import logging
import os

logger = logging.getLogger(__name__)

# Constants
NAN_THRESHOLD = 0.5
MIN_FLOW_DURATION = 0
FILLNA_VALUE = 0
INF_REPLACE_VALUE = 0

def preprocess_ddos_dataset(df):
    """
    Preprocesses the dataset with configuration.
    """
    try:
        logger.info("Starting data preprocessing...")
        df.columns = df.columns.str.strip().str.replace(" ", "_").str.lower()
        logger.debug(f"Standardized columns: {df.columns.tolist()}")

        if 'label' not in df.columns:
            logger.error("'label' column missing!")
            return None, None

        for col in df.columns:
            if col != "label":
                df[col] = pd.to_numeric(df[col], errors='coerce')
        logger.debug("Converted columns to numeric.")

        original_rows = df.shape[0]

        # Handle corrupt/invalid rows
        nan_threshold = float(os.environ.get('NAN_THRESHOLD', NAN_THRESHOLD))
        df = df[df.isnull().mean(axis=1) < nan_threshold]
        rows_dropped = original_rows - df.shape[0]
        logger.info(f"Removed {rows_dropped} rows with >{nan_threshold * 100}% missing values.")
        original_rows = df.shape[0]

        if 'flow_duration' in df.columns:
            min_flow_duration = int(os.environ.get('MIN_FLOW_DURATION', MIN_FLOW_DURATION))
            df = df[df['flow_duration'] > min_flow_duration]
            rows_dropped = original_rows - df.shape[0]
            logger.info(f"Removed {rows_dropped} rows with flow_duration <= {min_flow_duration}.")
            original_rows = df.shape[0]

        if 'total_fwd_packets' in df.columns:
            df = df[df['total_fwd_packets'] > 0]
            rows_dropped = original_rows - df.shape[0]
            logger.info(f"Removed {rows_dropped} rows with total_fwd_packets <= 0.")
            original_rows = df.shape[0]

        feature_cols = [col for col in df.columns if col != 'label']
        df = df[(df[feature_cols] != 0).any(axis=1)]
        rows_dropped = original_rows - df.shape[0]
        logger.info(f"Removed {rows_dropped} rows with all-zero features.")

        # Handle missing/infinite values
        fillna_value = int(os.environ.get('FILLNA_VALUE', FILLNA_VALUE))
        df.fillna(fillna_value, inplace=True)
        inf_replace_value = int(os.environ.get('INF_REPLACE_VALUE', INF_REPLACE_VALUE))
        df.replace([np.inf, -np.inf], inf_replace_value, inplace=True)
        logger.info(f"Filled NaN with {fillna_value} and infinite values with {inf_replace_value}.")

        # Encode labels
        label_encoder = LabelEncoder()
        df['label'] = label_encoder.fit_transform(df['label'].astype(str))
        logger.info("Encoded labels.")

        # Standardize numerical features
        numerical_cols = df.select_dtypes(include=['int64', 'float64']).columns.tolist()
        numerical_cols = [col for col in numerical_cols if col != 'label']

        if numerical_cols:
            scaler = StandardScaler()
            df[numerical_cols] = scaler.fit_transform(df[numerical_cols])
            logger.info("Standardized numerical features.")
        else:
            logger.warning("No numerical columns found for scaling.")

        logger.info("Data preprocessing completed successfully.")
        return df, label_encoder

    except Exception as e:
        logger.exception("Error during data preprocessing.")
        return None, None