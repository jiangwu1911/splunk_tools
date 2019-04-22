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
import json
import threading
from bottle import Bottle, run, response, request
from paste import httpserver
from time import gmtime, strftime
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

BASEDIR="/root/hnbank_alert/"
LOGFILE=BASEDIR+"send.log"
DBFILE=BASEDIR+"alerts.db"

RULE_ID="5c6136bf1c79f96ddd991204"
ORG=5001
SERVER_IP="10.18.20.142"
EASYOPS_CMDB_HOST="10.18.20.141"

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


CMDB_HEADERS = {'host': 'cmdb.easyops-only.com',    
                'org': str(ORG),    
                'user': 'easyops'}

# 向CMDBserver, 发送自定义请求
def cmdb_request(method, url, params=None):    
    logger.debug('Sending cmdb request: %s %s using params %s' % (method, url, str(params)))

    try:        
        if (method == "GET"):
            r = requests.get(url=url, 
                             headers=CMDB_HEADERS,
                             params=params)
        else:
            r = requests.post(url=url,
                             headers=CMDB_HEADERS, 
                             json=params)        
           
        if r.status_code == 200:            
            js = r.json()        
            if js['code'] == 0:
                return js
            else:
                logger.error(u'请求失败 ' + js['error'] + ' -- ' + str(params))
        else:            
            logger.error("Error: status_code = %s" % r.status_code)            
            logger.error("Error: error_info = %s" % r.text)            

    except Exception as e:        
        logger.error(e)        

    return None

def get_app_info(instanceId):
    search_url = 'http://{EASYOPS_CMDB_HOST}/object/APP/instance/_search'.format(EASYOPS_CMDB_HOST=EASYOPS_CMDB_HOST)    
    params = {"page": 1,
              "page_size": 3000,        
              "query": {"instanceId": {"$in": instanceId}},        
              "fields": { 
                   "name": True,            
                   "owner.name": True,        
                 }    
             }    
    app_info = []    
    try:        
        app_info = cmdb_request('POST', search_url, params=params)['data']["list"]    
    except Exception as e:        
        logger.error('Get cmdb instance error: %s ' % e)

    return app_info

def get_app_info_by_ip(ip):
    search_url = 'http://{EASYOPS_CMDB_HOST}/ip_related_info?ips={ip}'.format(EASYOPS_CMDB_HOST=EASYOPS_CMDB_HOST,                                                                              ip=ip)
    app_info_list = []
    appopers_list = []

    try:
        ret = cmdb_request('GET', search_url)
        if (len(ret['data']) > 0):
            app_ids = ret['data'][0].get("app_ids", "")
            app_info = get_app_info(app_ids)

            for app in app_info:
                app_info_list.append(app.get("name", ""))
                appopers = app.get("owner", "")
                appopers_list = []

                for i in appopers:
                    appopers_list.append(i.get("name", ""))

            app_info_list = sorted(set(app_info_list), key=app_info_list.index)
            appopers_list = sorted(set(appopers_list), key=appopers_list.index)

    except Exception as e:
        logger.error('Get cmdb instance error: %s ' % e)

    return app_info_list, appopers_list

def get_cmdb_info_by_ip(ip):
    search_url = 'http://{EASYOPS_CMDB_HOST}/object/HOST/instance/_search'.format(EASYOPS_CMDB_HOST=EASYOPS_CMDB_HOST)
    params = {
        "page": 1,
        "page_size": 3000,
        "query": {"$or": [{"ip": ip}, {"hostname": ip}]},
        "fields": {
            "hostname": True,
            "ip": True,
            "owner.name": True,
        }
    }

    info = {}
    try:
        result = cmdb_request('POST', search_url, params=params)

        if len(result['data']['list']) == 0:
            logger.error("IP %s not found in CMDB." % ip)
        else:    
            ret = result['data']['list'][0]
            hostname = ret.get("hostname", "")
            ip = ret.get("ip", "")
            hostopers = ret.get("owner", "")
            hostopers_list = []
            for oper in hostopers:
                hostopers_list.append(oper.get("name", ""))

            app_info, appopers = get_app_info_by_ip(ip)
            info = { "hostname": hostname,
                    "ip": ip,
                    "hostopers": hostopers_list,
                    "appinfo": app_info,
                    "appopers": appopers,
                    }

    except Exception as e:
        logger.error('Get cmdb instance error: %s ' % e)

    return info

def test_cmdb(ip):
    ret = get_cmdb_info_by_ip(ip)
    hostopers = ret.get("hostopers", "")
    
    for oper in hostopers:
        print(oper)



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
    
            result = self.send_alert(alert_id, host, message);
            if result == 0:
                cur.execute("UPDATE web_alerts SET status=1 WHERE id=?", [alert_id])
                db.commit()
            else:
                break;

        disconnect(db)

    # 调用自动化平台接口发送一条告警
    def send_alert(self, alert_id, host, message):
        # 先到CMDB中, 查出host的管理员
        # 注意这里的host是splunk日志中的host字段, 要确保host是真正产生日志的那台机器
        # 那种先把很多机器的日志通过syslog收集上来, 再用forwarder采集的情况, host是否有问题?
        ret = get_cmdb_info_by_ip(host)
        hostoper = ret.get("hostopers", "")
        oper_list = []
        for oper in hostoper:        
            oper_list.append({'name': oper, 'method': 'email'})
        logger.debug("oper_list is %s" % json.dumps(oper_list))

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
                "alert_dims": {
                     "ip": host 
                },
                "value": "-",
                "alert_receivers": oper_list
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
