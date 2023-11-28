vn_hosts = 5                        # No. of hosts ranges from 2 ~ 25
vn_duration = 60                    # Duration in seconds
pkt_injection_type = 'sequential'   # sequential or random
send_unique_pkts = True             # If True, ignore packet duplication and send unique packets only.

fixed_injection_time = False        # If True, packets injected after pkt_injection_time value. If False random time generated.
pkt_injection_time = 1              # This is a range starts from 0. Packets injected within this range at random interval.

fixed_timeout = 2                   # This is default timeout value for each flow if predict_timeout = False
ignore_tolerance = False            # There must be a tolerance in time to evacuate entity from a flow table. If True, tolerance will be ignored.

predict_timeout = False             # Simulate with or without predictive model
flow_table_threshold = 10           # Max number of flows in a flow table
threshold_safe_limit = 90           # Percentage of flow table threshold for safe limit. Considered for preactive deletion.

proactive_deletion = True           # If true, LRU flows will be removed from flow table when crossing threshold safe limit.

timeout_short_flow = 1              # Idle timeout value for short flows
timeout_medium_flow = 5             # Idle timeout value for medium flows
timeout_long_flow = 11              # Idle timeout value for long flows


# Machine Learning Model Files
ml_model_file = 'models/model_dtc.pkl'
ml_scaler_file = 'models/model_dtc_scaler.pkl'

# Log Files
injection_log_file = 'logs/log_injected_packets.csv'
prediction_log_file = 'logs/log_perdicted_timeout.csv'

flowtable_log_file = './logs/log_flowtable_occupancy.csv'
flowtable_summary_file ='./logs/summary_flowtable_occupancy.csv'

simulation_summary_file = 'logs/summary.txt'