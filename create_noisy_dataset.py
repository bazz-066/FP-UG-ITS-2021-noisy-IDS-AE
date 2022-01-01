import datetime
import numpy as np
import os
import pandas as pd
import shutil
import subprocess
import sys
import traceback

INCLUDED_ATTACKS = ["Exploits", "Backdoors", "Worms", "Shellcode"]

try:
    port = int(sys.argv[1])
    path = sys.argv[2]

    if len(sys.argv) == 4:
        benign_pcap = sys.argv[3]
    else:
        benign_pcap = None

    all_malicious_file = pd.read_csv("NUSW-NB15_GT.csv")
    all_malicious_file = all_malicious_file[(all_malicious_file["Destination Port"] == port)]
    malicious_file = all_malicious_file[(all_malicious_file["Attack category"] == "Exploits") | (all_malicious_file["Attack category"] == "Backdoors") | (all_malicious_file["Attack category"] == "Worms") | (all_malicious_file["Attack category"] == "Shellcode") ]
    malicious_file = malicious_file[(malicious_file["Destination Port"] == port)]
    malicious_file = malicious_file.reset_index(drop=True)
    #print(malicious_file.head())
    print("All malicious flows: ", len(all_malicious_file))
    
    # all_mal_tuples contains all malicious traffic, including DDoS and probes
    all_mal_tuples = ("combined-" + f'{port:05d}' + ".pcap." + all_malicious_file["Protocol"].str.upper() + "_" + all_malicious_file["Source IP"].str.replace(".", "-") + "_" + all_malicious_file["Source Port"].astype(str) + "_" + all_malicious_file["Destination IP"].str.replace(".", "-") + "_" + all_malicious_file["Destination Port"].astype(str) + ".pcap").values.tolist()
    # mal_tuples contains low-rate attacks that will be included in the training set
    mal_tuples = ("combined-" + f'{port:05d}' + ".pcap." + malicious_file["Protocol"].str.upper() + "_" + malicious_file["Source IP"].str.replace(".", "-") + "_" + malicious_file["Source Port"].astype(str) + "_" + malicious_file["Destination IP"].str.replace(".", "-") + "_" + malicious_file["Destination Port"].astype(str) + ".pcap").values.tolist()

    flows = os.listdir(path)
    num_traffic = len(flows)

    # read all files
    # check if they're malicious
    # if so, add it to the set if the limit is not met
    # if not, add it to the set
    mal_count = 0
    benign_filenames = []
    malicious_filenames = []

    for pcap_file in os.listdir(path):
        if pcap_file in mal_tuples:
            malicious_filenames.append(pcap_file)
            mal_count += 1
        elif pcap_file in all_mal_tuples:
            continue
        else:
            benign_filenames.append(pcap_file)

    num_benign = len(benign_filenames)
    max_percentage = float(mal_count)/float(num_traffic)

    print("Enter percentage (0-{}): ".format(max_percentage))
    percentage = float(input())

    num_malicious = int(percentage * 1/(1-percentage) * num_benign)
    print("Benign flows: ", num_benign)
    print("Malicious flows: ", num_malicious)
    #print(mal_tuples[:5])

    filenames = []
    if benign_pcap is None:
        filenames.extend(benign_filenames)
    else:
        num_benign = 0
    filenames.extend(malicious_filenames[:num_malicious])
    
    print("Expected num of flows: ", num_benign + num_malicious)
    print("Actual num of flows: ", len(filenames))

    merged_filename = "noisy_port-{}_percentage-{}.pcap".format(port, percentage)

    limit = 1000
    count = 0

    while count < len(filenames):
        command = ["mergecap", "-F", "pcap",  "-w", "tmp-{}-{}.pcap".format(port,percentage)]
        if count > 0:
            command.append("tmp2-{}-{}.pcap".format(port, percentage))
        elif benign_pcap is not None:
            command.append(benign_pcap)
        command.extend([(path + filename) for filename in filenames[count:count+limit]])
        #print(command[:20])
        start = datetime.datetime.now()
        subprocess.run(command)
        shutil.copy("tmp-{}-{}.pcap".format(port,percentage), "tmp2-{}-{}.pcap".format(port,percentage))
        count += limit
        end = datetime.datetime.now()
        timedelta = end - start
        sys.stdout.write("\rMerged {} files in {} ms".format(count, timedelta.microseconds))
        sys.stdout.flush()

    os.rename("tmp2-{}-{}.pcap".format(port,percentage), merged_filename)
except IndexError as e:
    print("usage: python3 create_noisy_dataset.py <port> <path> [clean_pcap_name]")
    traceback.print_exc(e)
