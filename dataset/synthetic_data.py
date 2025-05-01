# generate_synthetic_ddos_dataset.py

import pandas as pd
import numpy as np
import os

def generate_synthetic_ddos(num_samples=1000, output_file="dataset/test_logs_malicious.csv"):
    np.random.seed(42)

    data = {
        "flow_duration": np.random.randint(10000, 500000, num_samples),
        "total_fwd_packets": np.random.randint(100, 10000, num_samples),
        "total_backward_packets": np.random.randint(50, 1000, num_samples),
        "flow_bytes/s": np.random.uniform(1e5, 1e7, num_samples),
        "flow_packets/s": np.random.uniform(1000, 10000, num_samples),
        "syn_flag_count": np.random.randint(100, 500, num_samples),
        "ack_flag_count": np.random.randint(10, 50, num_samples),
        "psh_flag_count": np.random.randint(0, 10, num_samples),
        "urg_flag_count": np.zeros(num_samples),
        "down/up_ratio": np.random.uniform(0.001, 0.1, num_samples),
        "packet_length_std": np.random.uniform(100, 400, num_samples),
        "min_packet_length": np.random.randint(20, 100, num_samples),
        "max_packet_length": np.random.randint(500, 1500, num_samples),
        "total_length_of_fwd_packets": np.random.uniform(1e5, 1e6, num_samples),
        "total_length_of_bwd_packets": np.random.uniform(1000, 50000, num_samples),
        "init_win_bytes_forward": np.random.randint(100, 1000, num_samples),
        "bwd_packet_length_min": np.random.randint(20, 100, num_samples),
        "flow_iat_std": np.random.uniform(0.01, 1.0, num_samples),
        "flow_iat_max": np.random.uniform(0.1, 2.0, num_samples),
        "avg_fwd_segment_size": np.random.uniform(500, 1500, num_samples),
        "avg_bwd_segment_size": np.random.uniform(100, 500, num_samples),
        "subflow_fwd_packets": np.random.randint(100, 5000, num_samples),
        "subflow_bwd_packets": np.random.randint(50, 500, num_samples),
        "idle_max": np.random.uniform(0.5, 5.0, num_samples),
        "idle_min": np.random.uniform(0.1, 0.5, num_samples),
        "label": ["DDoS"] * num_samples
    }

    df = pd.DataFrame(data)
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    df.to_csv(output_file, index=False)
    print(f"[INFO] Synthetic malicious dataset created: {output_file}")

if __name__ == "__main__":
    generate_synthetic_ddos()