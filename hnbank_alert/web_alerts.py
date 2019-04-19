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
import bottle
import threading
from bottle import Bottle, run, response, request
from paste import httpserver
from time import gmtime, strftime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

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


# 单独线程, 不断从数据库中读取未发送的告警, 发送到自动化平台
class Publisher(threading.Thread):
    def __init__(self):
        threading.Thread.__init__(self)
        self.setDaemon(True)

    def run(self):
        while True:
            self.send_alerts()
            time.sleep(10)

    def send_alerts(self):
        db = connect_db()
        cur = db.cursor()

        cur.execute("SELECT id, search_name, result_host, result_message, \
                    datetime(create_time, 'localtime') \
                    FROM web_alerts WHERE status=0")
        for row in cur.fetchall():
            alert_id = row[0]
            search_name = row[1]
            host = row[2]
            content = row[3]
            message = "告警类型: %s\n主机:%s\n内容:%s" % (search_name, host, content)
            logger.debug(message)
    
            result = self.send_alert(alert_id, message);
            if result == 0:
                cur.execute("UPDATE web_alerts SET status=1 WHERE id=?", [alert_id])
                db.commit()
            else:
                break;

        disconnect(db)

    # 调用自动化平台接口发送一条告警
    def send_alert(self, alert_id, message):
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
                "level": 1,
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
            logger.info("Send alert failed, id=%d, message=%s" % (alert_id, message))
            logger.error(err)
        return(1)


# 把从web接口接收的告警, 存储在数据库中
def save_alert_to_db(reqest):
    db = connect_db()
    cur = db.cursor()

    j = request.json
    search_name = j['search_name']
    app = j['app']
    sid = j['sid']
    result_message = j['result']['_raw']
    result_host = j['result']['host']
    result_source = j['result']['source']
    result_sourcetype = j['result']['sourcetype']
    results_link = j['results_link']

    cur.execute("INSERT OR IGNORE INTO web_alerts( \
                        sid, search_name, app, result_message, result_host, \
                        result_source, result_sourcetype, results_link, create_time) \
                        VALUES(?,?,?,?,?,?,?,?,?)",
                        [ sid, search_name, app, result_message, result_host,
                          result_source, result_sourcetype, results_link,
                          strftime("%Y-%m-%d %H:%M:%S", gmtime()) ])
    db.commit()
    disconnect(db)

def define_route(app):
    @app.route('/')
    def server_index():
        return "Server used to send splunk alerts to operating platform."

    @app.post('/alerts')
    def new_alert():
        response.content_type = "application/json"
        return save_alert_to_db(request)

def main():
    app = Bottle()
    define_route(app)
    
    publisher = Publisher()
    publisher.start()

    httpserver.serve(app, host="0.0.0.0", port=8080, threadpool_workers=30, request_queue_size=20)
    #run(app, host="0.0.0.0", port=8080, debug=True)

if __name__ == "__main__":
    main()
