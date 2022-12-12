#!/usr/bin/env python3

"""Simple script to force a timeout failure in RESTAPI."""

import json
import os
import signal
import time

random_dic = {}

def signal_handler(signo, stack_frame):
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    f_path = os.path.join(cur_dir, f"{__file__}-RECV_SIGTERM")

    fh = open(f_path, 'w')
    fh.close()

    time.sleep(20)

if __name__ == "__main__":
    # Register the handler to advice caller of received signal
    signal.signal(signal.SIGTERM, signal_handler)

    # Forcing the timeout
    time.sleep(10)

    # Return random JSON
    for i in range(0, 20):
        random_dic["id_" + str(i)] = "0000000000"

    j_random_dic = json.dumps(random_dic)

    print(j_random_dic)
