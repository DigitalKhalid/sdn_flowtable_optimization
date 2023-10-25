import pandas as pd
from vn_settings import *

data = pd.read_csv(flowtable_log_file)

start_time = data['timestamp'].iloc[0]

step = 1 # seconds
log = {}
time = 0

for i in range(len(data)):
    if time in log and data['timestamp'].iloc[i] < start_time + step:
        if data['eviction_reason'].isnull().iloc[i]:
            log[time]['flows_added'] = log[time]['flows_added'] + 1
        else:
            if data['eviction_reason'].iloc[i] == 'IDLE TIMEOUT':
                if ignore_tolerance == False:
                    log[time]['idle_timeout_eviction'] = log[time]['idle_timeout_eviction'] + 1
        
            elif data['eviction_reason'].iloc[i] != 'IDLE TIMEOUT':
                log[time]['other_eviction'] = log[time]['other_eviction'] + 1

        if ignore_tolerance == False:
            log[time]['current_occupancy'] = data['flows'].iloc[i]
            last_occupancy = last_occupancy + 1
        
        else:
            log[time]['current_occupancy'] = log[time]['last_occupancy'] + log[time]['flows_added'] - log[time]['idle_timeout_eviction'] - log[time]['other_eviction']
            last_occupancy = log[time]['current_occupancy']

            if log[time]['current_occupancy'] < 0:
                log[time]['other_eviction'] = log[time]['other_eviction'] + log[time]['current_occupancy']
                log[time]['current_occupancy'] = 0

    else:
        start_time = data['timestamp'].iloc[i]
        time = time + 1

        if data['eviction_reason'].isnull().iloc[i]:
            idle_eviction = 0
            other_eviction = 0
            flow_added = 1
        else:
            if data['eviction_reason'].iloc[i] == 'IDLE TIMEOUT':
                if ignore_tolerance == True:
                    idle_eviction = log[time - fixed_timeout]['flows_added']

                else:
                    idle_eviction = 1

                other_eviction = 0
                flow_added = 0
            elif data['eviction_reason'].iloc[i] != 'IDLE TIMEOUT':
                idle_eviction = 0
                other_eviction = 1
                flow_added = 0

        try:
            last_occupancy = log[time-1]['current_occupancy']
        except:
            last_occupancy = 0

        log[time] = {
            'time': time,
            'last_occupancy': last_occupancy,
            'flows_added': flow_added,
            'idle_timeout_eviction': idle_eviction,
            'other_eviction': other_eviction,
            'current_occupancy': data['flows'].iloc[i],
        }


logs = pd.DataFrame.from_dict(log)
logs = logs.transpose()

logs.to_csv(flowtable_summary_file, index=False)

print('Done')