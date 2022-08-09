#!/usr/bin/env python

"""Simple script to force a timeout failure in RESTAPI."""

import time
import json

random_dic = {}

if __name__ == "__main__":
    # Forcing the timeout
    time.sleep(10)

    # Return random JSON
    for i in range(0, 20):
        random_dic["id_" + str(i)] = "0000000000"

    j_random_dic = json.dumps(random_dic)

    print(j_random_dic)
