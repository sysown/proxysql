#!/usr/bin/env python

"""Simple script to produce a 1MB output flushed in two times to be processed by the RESTAPI."""

import json
import time

random_dic = {}

if __name__ == "__main__":
    # Generate 1MB empty JSON
    for i in range(0, 40000):
        random_dic["id_" + str(i)] = "0000000000"

    j_random_dic = json.dumps(random_dic)

    # Split the string in half
    firstpart, secondpart = j_random_dic[:len(j_random_dic)//2], j_random_dic[len(j_random_dic)//2:]

    # Partial flush script
    print(firstpart, end='', flush=True)
    time.sleep(1)
    print(secondpart, end='', flush=True)
