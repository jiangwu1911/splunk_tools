#!/usr/bin/python 
import urllib
import httplib2
import sys
import configparser
import pathlib
from xml.dom import minidom
import mysql.connector
import json
import logging
from optparse import OptionParser

VERSION = "0.1"

SPLUNK_URL = 'https://192.168.206.212:8089'
SPLUNK_USER = 'admin'
SPLUNK_PASS = 'abcd1234'

MYSQL_HOST = 'localhost'
MYSQL_USER = 'root'
MYSQL_PASS = 'abc123'
MYSQL_DB = 'search'

logger = logging.getLogger("searchApp")
fmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
file_handler = logging.FileHandler('searchApp.log')
console_handler = logging.StreamHandler()
file_handler.setFormatter(fmt)
console_handler.setFormatter(fmt)

logger.addHandler(file_handler)
logger.addHandler(console_handler)
logger.setLevel(logging.INFO)

def main():
    usage = "Usage: %prog [options]"
    parser = OptionParser(usage)

    parser.add_option("-f", "--config", 
                      action="store", type="string",
                      dest="conf", help="Config file") 

    options, args = parser.parse_args()
    if options.conf == None:
        print("Usage: %s -f <config_file>" % sys.argv[0])
        exit(-1)

    file = pathlib.Path(options.conf)
    if not file.exists():
        print("File <%s> not found!" % options.conf)
        exit(-2)

    config = configparser.ConfigParser()
    config.read(options.conf)

    logger.info("%s started." % sys.argv[0])
    for item in config.items():
        if item[0] != "DEFAULT":
            result = run_search(config, item[0]) 
            save_to_mysql(config, item[0], result)
    logger.info('%s ended.' % sys.argv[0])


def run_search(config, item):
    spl = config[item]['spl']
    spl = spl.strip('"')
    if not (spl.startswith('search') or spl.startswith("|")):
        spl = 'search ' + spl

    sessionKey = ''
    try:
        serverContent = httplib2.Http(disable_ssl_certificate_validation=True).request(SPLUNK_URL +
            '/services/auth/login',
            'POST', headers={}, body=urllib.urlencode({'username':SPLUNK_USER, 'password':SPLUNK_PASS}))[1]
        sessionKey = minidom.parseString(serverContent).getElementsByTagName('sessionKey')[0].childNodes[0].nodeValue
    except:
        logger.error('SPLUNK login failed, check URL, username and password.')
        exit(-3)

    response = httplib2.Http(disable_ssl_certificate_validation=True).request(SPLUNK_URL +
            '/services/search/jobs/export',
            'POST',
            headers={'Authorization': 'Splunk %s' % sessionKey},
            body = urllib.urlencode({'search': spl, 'output_mode': 'json'}))
    status = response[0]['status']
    if int(status) >= 400:
        logger.error("Cannnot get result[%s] from SPLUNK, status is: %s" % (item, status))
        return ""

    result = response[1]
    return(result)


def save_to_mysql(config, item, result):
    if result == "":
        logger.error("Cannnot get result[%s] from SPLUNK." % item)
        return ""

    db = mysql.connector.connect(host=MYSQL_HOST, 
                                 user=MYSQL_USER, 
                                 password=MYSQL_PASS,
                                 database=MYSQL_DB)
    cursor = db.cursor()
    table = config[item]['table']

    for line in result.split('\n'):
        line = line.strip()
        if line == "":
            continue

        try:
            obj = json.loads(line)
        except:
            logger.error("Cannnot parse json: %s" % line)
            continue

        if obj.has_key('result'):
            cols1 = []
            cols2 = []
            vals = []

            sql = "INSERT INTO %s(" % table
            for o in config.options(item):
                if o=='table' or o=='spl':
                    continue

                cols1.append(o)
                cols2.append('%s')
                
                if obj['result'].has_key(o):
                    vals.append(obj['result'][o])
                else:
                    print("Error: %s not in result %s" % (o, line))

            sql = sql + ",".join(cols1) + ") values(" + ",".join(cols2)+")"
            logger.info(sql)
            logger.info(vals)
            cursor.execute(sql, vals)
            db.commit()

    logger.info("Data[%s] updated." % item)
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
