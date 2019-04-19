# -*- coding: UTF-8 -*-

import csv
import json
import requests
import uuid
import time
import logging

SPLUNK_ALERT_LOOKUP_FILE="/opt/splunk/splunk/etc/apps/search/lookups/alert.csv"
STATUS_FILE="alert_sent_status.json"

RULE_ID="5c6136bf1c79f96ddd991204"
ORG=5001
SERVER_IP="10.18.20.142"

def send_alert(alert):
    level_mapping = {'info': 0, 'warning': 1, 'critical': 2}
    body = { "rule_id": RULE_ID,
             "time": int(time.time()),
             "alert_id": str(uuid.uuid4()),
             "org": ORG,
             "is_recover": False,   
             "field": { 
                "content": alert['raw'],
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
    alert = {}
    alert['raw'] = "This is a test 2"
    result = send_alert(alert)
    
            
    if result == 0:
        logging.info("Success.") 
    else:
        logging.info("alert.py exit with error.") 
        sys.exit(-1)
