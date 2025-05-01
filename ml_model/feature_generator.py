import numpy as np
import pandas as pd

def advanced_feature_engineering(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()

    if all(col in df.columns for col in ['total_length_of_bwd_packets', 'total_length_of_fwd_packets']):
        df['amplification_ratio'] = df['total_length_of_bwd_packets'] / (df['total_length_of_fwd_packets'] + 1e-6)

    if all(col in df.columns for col in ['syn_flag_count', 'ack_flag_count']):
        df['syn_ack_discrepancy'] = (df['syn_flag_count'] - df['ack_flag_count']) / (df['syn_flag_count'] + df['ack_flag_count'] + 1e-6)

    if 'fwd_packets/s' in df.columns and 'total_fwd_packets' in df.columns and 'flow_duration' in df.columns:
        df['udp_frag_heuristic'] = (df['fwd_packets/s'] * df['total_fwd_packets']) / (df['flow_duration'] + 1e-6)

    if 'rst_flag_count' in df.columns and 'flow_duration' in df.columns:
        df['rst_per_sec'] = df['rst_flag_count'] / (df['flow_duration'] + 1e-6)

    if 'flow_iat_std' in df.columns and 'flow_iat_mean' in df.columns:
        df['burstiness'] = df['flow_iat_std'] / (df['flow_iat_mean'] + 1e-6)
        df['burstiness'] = df['burstiness'].replace([np.inf, -np.inf], 0)

    if all(col in df.columns for col in ['subflow_fwd_packets', 'subflow_bwd_packets']):
        df['subflow_imbalance'] = (df['subflow_fwd_packets'] - df['subflow_bwd_packets']) / (df['subflow_fwd_packets'] + df['subflow_bwd_packets'] + 1e-6)

    if all(col in df.columns for col in ['fwd_header_length', 'total_length_of_fwd_packets']):
        df['small_payload_ratio'] = df['fwd_header_length'] / (df['total_length_of_fwd_packets'] + 1e-6)

    if 'fin_flag_count' in df.columns and 'flow_packets/s' in df.columns:
        df['premature_fin'] = df['fin_flag_count'] * (1 / (df['flow_packets/s'] + 1e-6))

    return df