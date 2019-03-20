#!/usr/bin/env python

from __future__ import absolute_import
from __future__ import print_function
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from splunklib.client import connect

try:
    from utils import parse
except ImportError:
    raise Exception("Add the SDK repository to your PYTHONPATH to run the examples "
                    "(e.g., export PYTHONPATH=~/splunk-sdk-python.")

def main():
    opts = parse(sys.argv[1:], {}, ".splunkrc")
    service = connect(**opts.kwargs)

    for group in service.fired_alerts:
        header = "%s (count: %d)" % (group.name, group.count)
        print("%s" % header)
        print('='*len(header))
        alerts = group.alerts
        for alert in alerts.list():
            content = alert.content
            for key in sorted(content.keys()):
                value = content[key]
                print("%s: %s" % (key, value))
            print()

if __name__ == "__main__":
    main()
