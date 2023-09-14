import csv
import json
import requests
import asyncio
from timeout_predictor import timeout_predictor
import time


def add_log(log):
    file_name = 'log_packet_rate.csv'
    
    with open(file_name, 'a', newline = '') as logs:
        writer = csv.writer(logs)
        writer.writerow(log)


async def install_flow_entry(eth_src,
                             eth_dst,
                             ip_proto,
                             ip_src,
                             ip_dst,
                             tp_src,
                             tp_dst,
                             row_count):
    
    flowkey = ip_src + '-' + ip_dst + '-' + eth_src + '-' + eth_dst + '-' + ip_proto
    min_timeout = 1
    max_timeout = 11

    flow_entry={}
    flow_entry["dpid"] = "1"
    flow_entry["table_id"] = "0"

    flow_entry["idle_timeout"] = timeout_predictor(flowkey, min_timeout, max_timeout)

    match_obj={}
    if eth_src:
       match_obj['eth_src'] = eth_src

    if eth_dst:
        match_obj['eth_dst'] = eth_dst

    if ip_proto :
        match_obj['ip_proto'] = int(ip_proto)

    if ip_src:
        match_obj['eth_type'] = 2048
        match_obj['ipv4_src'] = ip_src
    if ip_dst:
        match_obj['eth_type'] = 2048
        match_obj['ipv4_dst'] = ip_dst

    if tp_src:
        match_obj['tp_src'] = tp_src

    if tp_dst:
        match_obj['tp_dst'] = tp_dst

    flow_entry['match'] = match_obj

    action_obj={}
    action_obj['type'] = "OUTPUT"
    action_obj['port'] = "10"

    flow_entry['actions'] = []
    flow_entry['actions'].append(action_obj)

    # all log
    log = [time.time(), flowkey]
    add_log(log)

    response = requests.post("http://localhost:8080/stats/flowentry/add", data = json.dumps(flow_entry))
    print(response.status_code)

    # if response.status_code == 200:
        # pass
    # else:
    #     print(response.status_code)


async def main():
    with open("univ1_pt0.csv",newline='') as csvfile:
        datapackets = csv.DictReader(csvfile)
        # a = asyncio.get_event_loop()
        tasks = []
        count = 0
        batch_size = 10
        row_count = 0

        for row in datapackets:
            count += 1
            row_count += 1
            print(json.dumps(row))

            tasks.append(
            install_flow_entry(row["eth.src"],
            row["eth.dst"],
            row["ip.proto"],
            row["ip.src"],
            row["ip.dst"],
            row["tcp.srcport"],
            row["tcp.dstport"],
            
            row_count))

            if count == batch_size:
                await asyncio.gather(*tasks, return_exceptions=False)
                tasks = []
                count = 0

asyncio.run(main())

#a.run_until_complete(main())