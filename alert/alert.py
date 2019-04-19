# -*- coding: UTF-8 -*-

import csv
import json
import requests
import uuid
import time
import logging

SPLUNK_ALERT_LOOKUP_FILE="/opt/splunk/splunk/etc/apps/search/lookups/alert.csv"
STATUS_FILE="/root/alert/alert_sent_status.json"

RULE_ID="5c6136bf1c79f96ddd991204"
ORG=5001
SERVER_IP="10.18.20.142"

# 读取上次发送到了哪一行 
def load_sent_position():
    try:
        with open(STATUS_FILE, 'r') as f:
            data = json.load(f)
        return(data['position'])
    except:
        return 0

# 保存发送到了哪一行
def save_sent_position(n):
    with open(STATUS_FILE, 'w') as f:
        data = { 'position': n }
        json.dump(data, f)

# 调用自动化平台接口发送告警
def send_alert(alert):
    level_mapping = {'info': 0, 'warning': 1, 'critical': 2}
    body = { "rule_id": RULE_ID,
             "time": int(time.time()),
             "alert_id": str(uuid.uuid4()),
             "org": ORG,
             "is_recover": False,   
             "field": { 
                "content": alert['raw'],
                #"content": "This is a test3",
                "target": "splunk"
             },
             "level": level_mapping.get(alert.get('leval'), 1),
             "alert_dims": {},
             "value": "-",
             "alert_receivers": [{'name' : 'chenmi','method' : 'sms'}] # [{'name': 'alren', 'method': 'sms'}]
            }

    try:
        result = requests.post("http://%s:8089/api/v1/alert/push_alert" % (SERVER_IP),
                          json=body,
                          headers = {'org': str(ORG)}) 

        if result.json().get('code') == 0:
            return(0)
    except:
        pass
    return(1)
         

if __name__ == '__main__':
    logging.basicConfig(filename='/root/alert/alert.log', 
                        format='%(asctime)s %(levelname)s %(message)s',
                        level=logging.DEBUG)
    logging.info("alert.py begin to run.")
    sent_position = load_sent_position()

    with open(SPLUNK_ALERT_LOOKUP_FILE, 'rb') as f:
        reader = csv.DictReader(f, delimiter=",", quotechar='"')

        lineno = 0;
        sent = 0

        for row in reader:
            lineno += 1
            if lineno > sent_position:
                alert = { 'lineno': lineno,
                          'raw': row['_raw'],
                          'serial': row['_serial'],
                          'sourcetype': row['_sourcetype'],
                          'time': row['_time']
                }
                result = send_alert(alert)
                
                
                if result == 0:
                    save_sent_position(lineno)
                    sent += 1
                else:
                    logging.info("alert.py exit with error.") 
                    sys.exit(-1)
    
        logging.info("alert.py run successfully, %s message sent." % sent)
