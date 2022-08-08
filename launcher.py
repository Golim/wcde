#!/usr/bin/env python3

__author__ = "Matteo Golinelli"
__copyright__ = "Copyright (C) 2022 Matteo Golinelli"
__license__ = "MIT"

from time import sleep

import subprocess
import argparse
import traceback
import random
import shlex
import json
import sys
import os

DEBUG = False
MAX = 5 # Max number of processes to run at once

crawler = 'wcde.py'
timeout = 5 # to kill hanging processes (in minutes)

# Tested sites
tested = []

def log(msg, file=sys.stdout):
    print(f'[LAUNCHER] {msg}', file=file, flush=True)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='launcher.py', description='Launch the crawler on a list of sites')

    parser.add_argument('-s', '--sites',                        help='Sites list', required=True)
    parser.add_argument('-m', '--max',        default=MAX,      help=f'Maximum number of sites to test concurrently (default: {MAX})')
    parser.add_argument('-t', '--testall',    default=False,    help='Test also already tested sites', action='store_true')
    parser.add_argument('-c', '--crawler',    default=crawler,  help='Alternative crawler script name to launch')
    parser.add_argument('-d', '--debug',      default=DEBUG,    action='store_true')

    args = parser.parse_args()

    if args.max:
        MAX = int(args.max)

    # Retrieve already tested sites from tested.json file
    if not args.testall and os.path.exists(f'logs/tested.json'):
        with open(f'logs/tested.json', 'r') as f:
            tested = json.load(f)


    if len(tested) > 0:
        random.shuffle(tested)
        log(f'Already tested sites ({len(tested)}): {", ".join(tested[:min(len(tested), 10)])}' +
            f'... and {len(tested) - min(len(tested), 10)} more')

    sites = []
    try:
        with open(args.sites, 'r') as f:
            sites = [s.strip() for s in f.readlines()]

        random.shuffle(sites)

        processes = {}

        for site in sites:
            try:                
                if site != '' and site in tested and not args.testall:
                    continue
                
                first = True # Execute the loop the first time regardless
                # Loop until we have less than MAX processes running
                while len(processes) >= MAX or first:
                    first = False

                    for s in processes.keys():
                        state = processes[s].poll()

                        if state is not None: # Process has finished
                            del processes[s]
                            print(f'[LAUNCHER] [{len(tested)}/{len(sites)} ({len(tested)/len(sites)*100:.2f}%)] {s} tested, exit-code: {state}.')
                            if state == 0:
                                tested.append(s)
                                with open(f'logs/tested.json', 'w') as f:
                                    json.dump(tested, f)
                            break
                    sleep(1)

                # When we have less than MAX processes running, launch a new one
                if site != '' and site not in tested:
                    cmd  = f'python3 {args.crawler} -t {site}'
                    log(f'Testing {site}')
                    try:
                        p = subprocess.Popen(shlex.split(cmd))
                        processes[site] = p
                        # print('\t\t >>>', cmd)
                    except subprocess.TimeoutExpired as e:
                        log(f'Timeout expired for {site}')
                    except subprocess.CalledProcessError as e:
                        log(f'Could not test site {site}', file=sys.stderr)
                    except Exception as e:
                        log(f'Could not test site {site}', file=sys.stderr)
                        traceback.print_exc()
            except Exception as e:
                log(f'Error [{site}] {e}', file=sys.stderr)
                traceback.print_exc()
    except KeyboardInterrupt:
        log('Keyboard interrupt')
    except:
        log(traceback.format_exc(), file=sys.stderr)
    finally:
        log(f'Tested sites ({len(tested)}): {", ".join(tested[:min(len(tested), 10)])}' +
            f'... and {len(tested) - min(len(tested), 10)} more')
