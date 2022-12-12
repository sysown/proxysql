#!/usr/bin/env python3

"""Simple script returning a valid empty result for RESTAPI."""

import json
import time
import os
import signal
import sys

def print_inv_json():
    print("invalid_json", file=sys.stdout, flush=False, end="")

def print_random_dic():
    random_dic = {}

    for i in range(0, 4000000):
        random_dic["id_" + str(i)] = "0000000000"

    j_random_dic = json.dumps(random_dic)
    print(j_random_dic, file=sys.stderr)

def close_stdout():
    sys.stdout.close()
    os.close(1)

def close_stderr():
    sys.stdout.close()
    os.close(0)

def flush_stderr():
    sys.stderr.flush()

def simple_print_and_flush(stdout=True):
    if stdout:
        print("{}", file=sys.stdout, flush=True, end="")
    else:
        print("{}", file=sys.stderr, flush=True, end="")

def signal_handler(signo, stack_frame):
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    f_path = os.path.join(cur_dir, f"{__file__}-RECV_SIGTERM")

    fh = open(f_path, 'w')
    fh.close()

    time.sleep(20)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, signal_handler)
    simple_print_and_flush(stdout=True)
    close_stdout()
    close_stderr()

    time.sleep(10)
