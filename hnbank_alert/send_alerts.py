#!/usr/bin/env python
#
# Copyright 2019 SinoBridge
# Author: wujiang
# 
# Read alerts from splunk, then send them to YouWei Operation center
#

from __future__ import absolute_import
from __future__ import print_function
import sys, os
import logging
import sqlite3
from time import gmtime, strftime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from splunklib.client import connect

try:
    from utils import parse
except ImportError:
    raise Exception("Add the SDK repository to your PYTHONPATH to run the examples "
                    "(e.g., export PYTHONPATH=~/splunk-sdk-python.")

BASEDIR="/home/jwu/splunk_tools/hnbank_alert/"
LOGFILE=BASEDIR+"send.log"
DBFILE=BASEDIR+"alerts.db"

logging.basicConfig(filename=LOGFILE,
                    level=logging.DEBUG,
                    format='%(asctime)s.%(msecs)03d %(levelname)s %(funcName)s(): %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()

def connect_db():
    return sqlite3.connect(DBFILE)

def disconnect(conn):
    conn.close

def read_alerts_from_splunk():
    opts = parse(sys.argv[1:], {}, ".splunkrc")
    service = connect(**opts.kwargs)

    db = connect_db()
    cur = db.cursor()

    for group in service.fired_alerts:
        header = "%s (count: %d)" % (group.name, group.count)
        logger.debug("%s" % header)
        logger.debug('='*len(header))
        alerts = group.alerts

        for alert in alerts.list():
            content = alert.content
            for key in sorted(content.keys()):
                value = content[key]
                logger.debug("%s: %s" % (key, value))
            logger.debug("")

            if group.name != "-":
                cur.execute("INSERT INTO alerts(sid, alert_group, savedsearch_name, alert_type, digest_mode, \
                        severity, expiration_time, create_time) \
                        VALUES(?,?,?,?,?,?,?,?)",
                        [ content.get('sid', ''),
                          group.name,
                          content.get('savedsearch_name', ''),
                          content.get('alert_type', ''),
                          int(content.get('digest_mode', '0')),
                          int(content.get('severity', '0')),
                          content.get('expiration_time_rendered', ''),
                          strftime("%Y-%m-%d %H:%M:%S", gmtime())                           
                        ])

    db.commit()
    disconnect(db)
    return service.fired_alerts

def main():
    read_alerts_from_splunk()

if __name__ == "__main__":
    main()

