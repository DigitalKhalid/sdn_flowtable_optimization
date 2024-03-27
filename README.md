# sdn_flowtable_optimization
----------------------------------------------------------------------------------------------
Software Defined Network (SDN) Flow Table Optimization using Machine Learning 
----------------------------------------------------------------------------------------------
A project for PhD Research Paper

----------------------------------------------------------------------------------------------
Pre-requisites to run virtual network simulation
----------------------------------------------------------------------------------------------
- Ubuntu 22.04.3 LTS
- Install Python 3.9.0 
    - Open the link below and follow the procedure to install:
      https://www.linuxcapable.com/how-to-install-python-3-9-on-ubuntu-linux/
      
- Open terminal and install following packages using root privileges:
    - Mininet, Pandas, Scapy, hping3, scikit-learn
        - sudo apt-get install mininet pandas scapy hping3 scikit-learn

- Make a new directory and sub directories as follows:
    - Paste following files in the main directory:
        - help.txt, README.md, requirements.txt, start.sh
    - Make sub directory named 'datasets' and paste data files in this directory
    - Make sub directory named 'models' and paste model files in this directory
    - Make sub directory named 'app' and paste all python files in this directory
    - Make empty sub directory named 'logs'

- Open terminal from the main directory
- Create virtual environment using command: python3.9 -m venv venv
- Active the virtual environment using command: source venv/bin/activate
- Now install other packages using command: python3 -m pip install -r requirements.txt

----------------------------------------------------------------------------------------------
Settings to customize virtual network simulation
----------------------------------------------------------------------------------------------
- You can customize simulation by changing the values of variables given in file: vn_settings.py
- There are following settings available:
    - vn_host
        - This is virtual network host created by mininet.
        - Default value is 5. You can set the value upto 25.

    - vn_duration
        - This is virtual network duration in seconds.
        - Default value is 30.

    - pkt_injection_type
        - This defines how packets will inject from the source file.
        - There are two options available:
            - sequential
                - It will send the packets from source file in a sequenced manner.
            - random
                - It will send the packets from the source file in a random order.

    - send_unique_packets
        - If True, ignore packet duplication and send unique packets only

    - fixed_injection_time
        - True: Each packet injected after time given in pkt_injection_time
        - False: Each packet injected after random generated time

    - pkt_injection_time
        - This is the delay in seconds to send the packets ranges from 0 to the given value.
        - Default value is 0.05 means packets sends by the delay randomly choosen between 0 and 0.05.
        - If fixed_injection_time is set to True, no random time is used.

    - fixed_timeout
        - If predict_timeout is set to False then this time will be used as idle timeout for each flow entry.

    - predict_timeout
        - True: Predicted timeout value using machine learning model is used as idle timeout for respective flow.
        - False: fixed_timeout value is used as idle timeout for each flow entry. No predictive model is utilized.
    
    - flow_table_threshold          
        - Max number of flows in a flow table

    - threshold_safe_limit
        - Percentage of flow table threshold for safe limit. Considered for preactive deletion

    - proactive_deletion
        - If true, LRU flows will be removed from flow table when crossing threshold safe limit

    - timeout_short_flow
        - Idle timeout value for short flows

    - timeout_medium_flow
        - Idle timeout value for medium flows

    - timeout_long_flow
        - Idle timeout value for long flows

    - DATASET
        - Select dataset to be used during simulation. Options are 'univ2' and 'mawi'.

    - All other variables are path and names of files used in simulation or created by simulation. You can change the files as you require.

----------------------------------------------------------------------------------------------
How to run virtual network?
----------------------------------------------------------------------------------------------
- Open the terminal from the main directory.
- Use command: ./start.sh (Its needs root pervilages hence asked for password.)
- This command will do the following:
    - Run Mininet Cleanup to remove previous instance of virtual network if any.
    - Run Ryu Rest API.
    - Start Ryu Controller.
    - Create a network topology.
    - Start Injecting Packets to the network.
    - The whole process will run for a specificed period of time and then stops.
    - Create log file for packet injection.
    - Create log file for predicted timeouts.
    - Create log file for flow table occupancy.
    - Create summary file. Log files and summary files will be created in logs folder.
- To get the summary of flowtable occupancy:
    - Use command: ./summary.sh

----------------------------------------------------------------------------------------------
How to generate summary of flowtable occupancy?
----------------------------------------------------------------------------------------------
- Open the terminal from the main directory.
- Use command: ./summary.sh
- This command will do the following:
    - Create summary of flowtabel occupancy. Log files and summary files will be created in logs folder.

----------------------------------------------------------------------------------------------
How to get latency of injected packets?
----------------------------------------------------------------------------------------------
- You calculate latency, you need to capture the packets using WireShark during simulation. 
- Export the captured log as csv file having same columns as packet_injection_log.csv file
- Rename the captured log file as log_captured_packets.csv
- Copy this file in logs directory
- Open the terminal from the main directory.
- Use command: ./latency.sh
- This command will do the following:
    - Create latency log file. Log files and summary files will be created in logs folder.

----------------------------------------------------------------------------------------------
Asumptions
----------------------------------------------------------------------------------------------
- We are sending flows from the dataset extracted from the MAWI packet trace data.

----------------------------------------------------------------------------------------------
Packet Capturing
----------------------------------------------------------------------------------------------
You can capture the packets using WireShark. Open WireShark using following command:
    - sudo wireshark

----------------------------------------------------------------------------------------------
Thank you.
For more information, please email: po.mwts@gmail.com
----------------------------------------------------------------------------------------------
