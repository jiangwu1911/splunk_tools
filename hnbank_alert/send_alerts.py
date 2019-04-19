# -*- coding: UTF-8 -*-
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
import requests
import uuid
import time
from time import gmtime, strftime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from splunklib.client import connect

BASEDIR="/home/jwu/splunk_tools/hnbank_alert/"
LOGFILE=BASEDIR+"send.log"
DBFILE=BASEDIR+"alerts.db"

RULE_ID="5c6136bf1c79f96ddd991204"
ORG=5001
SERVER_IP="192.168.206.106"

try:
    from utils import parse
except ImportError:
    raise Exception("Add the SDK repository to your PYTHONPATH to run the examples "
                    "(e.g., export PYTHONPATH=~/splunk-sdk-python.")

logging.basicConfig(filename=LOGFILE,
                    level=logging.DEBUG,
                    format='%(asctime)s.%(msecs)03d %(levelname)s %(funcName)s(): %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S')
logger = logging.getLogger()

def connect_db():
    return sqlite3.connect(DBFILE)

def disconnect(conn):
    conn.close

# 从splunk中读取告警
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
                cur.execute("INSERT OR IGNORE INTO alerts( \
                        sid, alert_group, savedsearch_name, alert_type, digest_mode, \
                        severity, expiration_time, create_time) \
                        VALUES(?,?,?,?,?,?,?,?)",
                        [ content.get('sid', ''),
                          group.name,
                          content.get('savedsearch_name', ''),
                          content.get('alert_type', ''),
                          int(content.get('digest_mode', '0')),
                          int(content.get('severity', '0')),
                          content.get('expiration_time_rendered', ''),
                          # Time insert using timezone GMT
                          # SELECT datetime(create_time,'localtime') FROM alerts can get the correct value
                          strftime("%Y-%m-%d %H:%M:%S", gmtime())
                        ])

    db.commit()
    disconnect(db)
    return service.fired_alerts

# 从数据库中读取未发送的告警, 发送到优维平台
def send_alerts_to_youwei():
    db = connect_db()
    cur = db.cursor()

    cur.execute("SELECT id, alert_group, savedsearch_name, alert_type, severity, \
                 datetime(create_time, 'localtime') FROM alerts WHERE status=0")
    for row in cur.fetchall():
        alert_id = row[0]
        alert_type = row[1]
        severity = row[4]
        content = row[2]
        message = "告警类型: %s\n告警级别:%s\n内容:%s" % (alert_type, severity, content)
        logger.debug(message)

        result = send_alert(alert_id, severity, message);
        if result == 0:
            cur.execute("UPDATE alerts SET status=1 WHERE id=?", [alert_id])
            db.commit()

    disconnect(db)

# 调用自动化平台接口发送一条告警
def send_alert(alert_id, severity, message):
    level_mapping = {'debug':1, 'info':2, 'warn':3, \
                     'error':4, 'severe':5, 'fatal':6}
    body = { "rule_id": RULE_ID,
             "time": int(time.time()),
             "alert_id": str(uuid.uuid4()),
             "org": ORG,
             "is_recover": False,
             "field": {
                "content": message,
                "target": "splunk"
             },
             "level": level_mapping.get(severity),
             "alert_dims": {},
             "value": "-",
             "alert_receivers": [{'name' : 'chenmi','method' : 'sms'}]
            }
    try:
        result = requests.post("http://%s:8089/api/v1/alert/push_alert" % (SERVER_IP),
                          json=body,
                          headers = {'org': str(ORG)})
        if result.json().get('code') == 0:
            logger.info("Send alert successfully, id=%d, message=%s" % (alert_id, message))
            return(0)
    except:
        err = sys.exc_info()[1]
        logger.error(err)
        logger.info("Send alert failed, id=%d, message=%s" % (alert_id, message))
    return(1)

def main():
    read_alerts_from_splunk()
    send_alerts_to_youwei()

if __name__ == "__main__":
    main()

