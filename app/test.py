# Sample dictionary with cookie_id as keys and timestamps as values
cookie_timestamps = {
    'cookie1': '2023-10-27 10:00:00',
    'cookie2': '2023-10-27 09:30:00',
    'cookie3': '2023-10-27 11:15:00',
    'cookie4': '2023-10-27 08:45:00',
    'cookie5': '2023-10-27 11:30:00'
}

# Sort the dictionary by timestamp (convert timestamps to datetime objects for proper sorting)
LRU_flows = dict(sorted(cookie_timestamps.items(), key=lambda item: item[1], reverse=False))

# Get the last 3 items from the sorted dictionary
LRU_flows = list(LRU_flows)[:3]

# Print the result
print(LRU_flows)