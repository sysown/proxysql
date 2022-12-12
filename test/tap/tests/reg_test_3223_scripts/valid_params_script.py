#!/usr/bin/env python3

"""Simple script returning its params as result for the RESTAPI."""

import json
import sys

if __name__ == "__main__":
    param_num = len(sys.argv)

    if param_num == 2:
        exp_args = json.loads(sys.argv[1])
        print(sys.argv[1])

        if len(exp_args):
            arg1 = exp_args["param1"]
            arg2 = exp_args["param2"]

            exp_arg1 = arg1 == "value1" or arg1 == "'value1'"
            exp_arg2 = arg2 == "value2" or arg2 == "'value2'" or arg2 == "'\"value2\"'"

            sys.exit(not (exp_arg1 and exp_arg2))
        else:
            sys.exit(0)
    else:
        print(json.dumps({"error": f"Invalid number of params - exp: '2', act: '{param_num}'"}))
        sys.exit(1)
