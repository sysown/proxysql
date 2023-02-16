#!/usr/bin/env python3

"""Simple script that writes a dummy output to the specified standard stream."""

import sys
import time
import os
import signal

def signal_handler(signo, stack_frame):
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    f_path = os.path.join(cur_dir, f"{__file__}-RECV_SIGTERM")

    fh = open(f_path, 'w')
    fh.close()

    time.sleep(20)

if __name__ == "__main__":
    param_num = len(sys.argv)

    if param_num == 2:
        # Register the handler to advice caller of received signal
        signal.signal(signal.SIGTERM, signal_handler)

        if sys.argv[1] == "stdout":
            print("dummy_stdout_output", file=sys.stdout, flush=True, end='')
        elif sys.argv[1] == "stderr":
            print("dummy_stderr_output", file=sys.stderr, flush=True, end='')
        else:
            pass

        # Ensure that we are killed by timeout
        time.sleep(20)
    else:
        sys.exit(1)
