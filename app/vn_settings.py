vn_hosts = 5                        # No. of hosts ranges from 2 ~ 25
vn_duration = 100                    # Duration in seconds
pkt_injection_type = 'sequential'   # sequential or random
pkt_injection_time = 0.05           # This is a range starts from 0. Packets injected within this range at random interval.
predict_timeout = True              # Simulate with or without predictive model
flow_table_threshold = 1000          # Max number of flows in a flow table
min_timeout = 1                     # Mininum timeout value to be set (used as default timeout)
# max_timeout = 11                    # Maximum timeout value to be set (used as hard timeout)
timeout_short_flow = 1              # Idle timeout value for short flows
timeout_medium_flow = 5             # Idle timeout value for medium flows
timeout_long_flow = 11              # Idle timeout value for long flows