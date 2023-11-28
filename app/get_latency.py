import pandas as pd
from vn_settings import *

def get_latency_log(injected_packets_file, captured_packets_file, output_file):
    # Read CSV files into pandas DataFrames
    df1 = pd.read_csv(injected_packets_file)
    df2 = pd.read_csv(captured_packets_file)

    matching_columns = ['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']
    merged_df = pd.merge(df1, df2, on=matching_columns, how='left')

    merged_df['latency'] = merged_df['timestamp_y'] - merged_df['timestamp_x']

    merged_df = merged_df.rename(columns={'timestamp_x': 'injection_time'})
    merged_df = merged_df.rename(columns={'timestamp_y': 'arrival_time'})

    columns = ['injection_time', 'arrival_time', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'latency']
    merged_df = merged_df[columns]

    # Save the merged DataFrame to a new CSV file
    merged_df.to_csv(output_file, index=False)


if __name__ == '__main__':
    get_latency_log(injection_log_file, captured_log_file, latency_log_file)
    print('Latency log generated.')
