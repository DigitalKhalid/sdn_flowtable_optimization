import requests
import asyncio
import json
import csv
import time
from requests.exceptions import HTTPError

entries_limit = 10
safe_limit_percentage = 90

entries_safe_threshold = entries_limit * safe_limit_percentage / 100

previous_flow_entries = 0
new_flow_entries = 0

async def every(__seconds: float, func, *args, **kwargs):
    while True:
        func(*args, **kwargs)
        await asyncio.sleep(__seconds)


def add_log(log):
    file_name = 'log_flow_table.csv'
    
    with open(file_name, 'a', newline = '') as logs:
        writer = csv.writer(logs)
        writer.writerow(log)


def get_flow_stats():
   try:
    response = requests.get("http://localhost:8080/stats/flow/1")
    response.raise_for_status()

   except HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')

   except Exception as err:
        print(f'Other error occurred: {err}')

   else:
        pass

   entries = response.json()
   sorted_list = sorted(entries['1'], key = lambda entry:entry["packet_count"])
   
   flowkeys = []
   for flow_entry in sorted_list:
    match = flow_entry['match']
    try:
        eth_src = match['dl_src']
        eth_dst = match['dl_dst']
        ipv4_src = match['nw_src']
        ipv4_dst = match['nw_dst']
        ip_proto = match['nw_proto']

        flowkeys.append(ipv4_src + '-' + ipv4_dst + '-' + eth_src + '-' + eth_dst + '-' + ip_proto)

        log = [time.time(), len(sorted_list), flowkeys]
        add_log(log)

    except:
        pass

   global new_flow_entries
   global previous_flow_entries

   new_flow_entries = len(sorted_list) - previous_flow_entries
   previous_flow_entries = len(sorted_list)
#    print(f'Previous Flow Entries: {previous_flow_entries}, New Flow Entries: {new_flow_entries}')

   return sorted_list


# Aggressive Deletion of LRU Flows from the Flow Table if safe threshold crossed
def aggressive_deletion(entries):
    entries_count = len(entries)
    if entries_count <= entries_safe_threshold:
        print("No flow eviction required")
    
    else:
        deletion_count = entries_count - entries_safe_threshold
        deleted_count = 0

        for entry in entries:
            if deleted_count <= deletion_count:
                print(f'Sending deletion request for {entry}')
                response = requests.post("http://localhost:8080/stats/flowentry/delete", data = json.dumps(entry))
                deleted_count += 1
                print(f'Response received {response}')


# Deletion of LRU flows to accomodate the predicted incomming flows if space not available in flow table
def proactive_deletion(entries, previous_flow_entries, new_flow_entries):
    if new_flow_entries > 0:
        total_entries = previous_flow_entries + new_flow_entries

        if total_entries >= entries_safe_threshold:
            deletion_count = (total_entries - entries_safe_threshold) + new_flow_entries
            deleted_count = 0

            for entry in entries:
                if deleted_count <= deletion_count:
                    # print(f'Sending deletion request for {entry}')
                    response = requests.post("http://localhost:8080/stats/flowentry/delete", data = json.dumps(entry))
                    deleted_count += 1
                    # print(f'Response received {response}')
            print(f'{deleted_count} flow entries out of {total_entries} deleted by proactive deletion as the safe limit was {entries_safe_threshold}.')


def task_every_sec():
    flowtable_entries = get_flow_stats()
    proactive_deletion(flowtable_entries, previous_flow_entries, new_flow_entries)

loop = asyncio.get_event_loop()
loop.create_task(every(1, task_every_sec))
loop.run_forever()
