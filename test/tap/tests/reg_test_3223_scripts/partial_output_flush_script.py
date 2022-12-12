#!/usr/bin/env python3

"""Simple script to produce a 1MB output flushed in two times to be processed by the RESTAPI."""

import json
import textwrap
import time
import sys

random_dic = {}

if __name__ == "__main__":
    # Generate 1MB empty JSON
    for i in range(0, 40000):
        random_dic["id_" + str(i)] = "0000000000"

    j_random_dic = json.dumps(random_dic)
    parts = textwrap.wrap(j_random_dic, len(j_random_dic)//10)

    for part in parts:
        print(part, file=sys.stdout, flush=True, end='')
        time.sleep(0.5)
