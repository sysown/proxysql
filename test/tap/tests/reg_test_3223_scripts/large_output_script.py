#!/usr/bin/env python3

"""Simple script to produce a 1MB output to be processed by the RESTAPI."""

import json

random_dic = {}

##
# @brief Return the length of the encoded string, output gives an stimation
#  of string size in bytes.
# @param s The string which size is to be measured.
# @return The length of the result of encoding the supplied string in 'utf-8'
def utf8len(s):
    return len(s.encode('utf-8'))

if __name__ == "__main__":
    # Return big random JSON
    for i in range(0, 40000):
        random_dic["id_" + str(i)] = "0000000000"

    j_random_dic = json.dumps(random_dic)

    # print(utf8len(j_random_dic))
    print(j_random_dic)
