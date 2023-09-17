import csv
import time


def load_logs(file_name):
    with open(file_name, 'r') as log:
        reader = csv.reader(log)
        logs = list(reader)
    return logs


def update_log(file_name, logs):
    with open(file_name, 'w', newline = '') as log:
        writer = csv.writer(log)
        writer.writerows(logs)

    
def get_timeout(logs, flow_key, timestamp, min_timeout, max_timeout):
    headers = logs[0]  # First row contains headers
    flow_keys = headers.index('flow_key')
    packet_intervals = headers.index('packet_interval')
    last_packet_time = headers.index('last_packet_time')
    
    for row in logs:
        if row[flow_keys] == flow_key:
            timeout = int(row[packet_intervals])
            
            if float(row[last_packet_time]) > 0:
                new_timeout = timestamp - float(row[last_packet_time])

                if new_timeout > timeout:
                    # print(f'new_timout value {new_timeout}')
                    if new_timeout <= max_timeout: 
                        timeout = int(new_timeout)

#                     else:
#                         timeout = max_timeout

                    row[packet_intervals] = timeout

            row[last_packet_time] = timestamp
            break
            
        else:
            timeout = 0

    if timeout == 0:
        timeout = min_timeout
        new_log = [flow_key, timeout, timestamp]
        logs.append(new_log)
    
    return timeout, logs


def timeout_predictor(packet_flowkey, min_timeout, max_timeout):
    # Load log file
    input_file = 'extracted_features_5.csv'
    logs = load_logs(input_file)

    # Get timeout value
    timeout, logs = get_timeout(logs, packet_flowkey, time.time(), min_timeout, max_timeout)

    # Update logs
    update_log(input_file, logs)

    return timeout

# def timeout_predictor(match, min_timeout, max_timeout):
#     # Get packet information
#     # packet_flowkey = '41.177.26.15-15.71.149.241-00:03:ba:24:40:1b-00:00:0c:07:ac:00-6.0'
#     source_ip = match.ipv4_src
#     destination_ip = match.ipv4_dst
#     source_mac = match.eth_src
#     destination_mac = match.eth_dst
#     protocol = match.ip_proto

#     packet_flowkey = source_ip + '-' + destination_ip + '-' + source_mac + '-' + destination_mac + '-' + protocol

#     # Load log file
#     input_file = 'extracted_features_5.csv'
#     logs = load_logs(input_file)

#     # Get timeout value
#     timeout, logs = get_timeout(logs, packet_flowkey, time.time(), min_timeout, max_timeout)

#     # Update logs
#     update_log(input_file, logs)

#     print(f'Predicted Timeout is {timeout}')