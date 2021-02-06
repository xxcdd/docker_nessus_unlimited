#!/usr/bin/python
# coding:utf-8
import commands
import socket
import sys

import requests
import string
import random
import time
import json
import re
import os
import time
from bs4 import BeautifulSoup
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)


def port_open():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    errno = s.connect_ex(('127.0.0.1', 8834))
    s.close()
    if errno == 0:
        return True
    return False


# check ui ready or not
def check_status():
    url = 'https://127.0.0.1:8834'
    while True:
        if port_open():
            time.sleep(5)
            try:
                resp = requests.get(url + '/nessus6.js?v=1607644926568', verify=False)
                token_re = re.findall('key:"getApiToken",value:function\(\){return"([\w-]+)"', resp.content)
                token = token_re[0]
                print token
                resp = requests.get(url + '/server/status', verify=False, headers={
                    "Content-Type": "application/json",
                    "X-API-Token": token
                })
                print resp.content
                if json.loads(resp.content)["status"] == "ready":
                    break
            except Exception as e:
                print e
        else:
            time.sleep(2)


def str_count(count):
    return ''.join(random.choice(string.letters + string.digits) for i in range(count))


def write_inc():
    with open('plugin_feed_info.inc', 'w') as f:
        f.write("""PLUGIN_SET = "202006091543";
    PLUGIN_FEED = "ProfessionalFeed (Direct)";

    PLUGIN_FEED_TRANSPORT = "Tenable Network Security Lightning";""")


def get_plugin():
    headers = {
        "Connection": "close",
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.138 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Accept-Language": "zh-CN,zh;q=0.9,es;q=0.8,fr;q=0.7,vi;q=0.6"
    }
    # proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
    proxies = {}

    mailx = str(str_count(9).lower())
    domain = "getnada.com"

    email = mailx + '@getnada.com'
    print ("生成的Email地址: {mail}".format(mail=email))
    regurl = "https://zh-cn.tenable.com/products/nessus/nessus-essentials?tns_redirect=true"
    print ("开始获取Nessus注册相关的表单")
    tkn = ""
    try:
        ht = requests.get(regurl, headers=headers, verify=False, proxies=proxies, timeout=600)
        bs = BeautifulSoup(ht.text, 'html.parser')
        for link in bs.findAll("input", {"name": "token"}):
            if 'name' in link.attrs:
                tkn = link.attrs['value']
            else:
                print("没有在当前页面找到token")
    except Exception as e:
        print '[get token] {}'.format(e.message)
        pass
    print ("获取到Nessus注册token为\t{token}".format(token=tkn))
    if not tkn:
        print ("fail, please check")
        return
    comurl = "https://www.tenable.com/products/nessus/nessus-essentials"
    params = {"first_name": str(str_count(9).lower()), "last_name": str(str_count(9).lower()), "email": email,
              "country": "IN", "Accept": "Agree",
              "robot": "human", "type": "homefeed", "token": tkn, "submit": "Register"}
    try:
        r = requests.post(comurl, headers=headers, data=params, verify=False, proxies=proxies, timeout=600)
    except Exception as e:
        print '[reg] {}'.format(e.message)
        pass
    all = mailx + "@" + domain
    print ("注册成功，等待到邮箱 {mail} 去获取相关的信息".format(mail=all))
    GET_INBOX = 'https://getnada.com/api/v1/inboxes/'
    boxurl = GET_INBOX + all
    sleep = 15
    print ("需要等待一段时间({sleep}秒)，等待邮箱收信有一定的延迟".format(sleep=sleep))

    time.sleep(sleep)
    try:
        r = requests.get(boxurl, headers=headers, proxies=proxies, timeout=600, verify=False)
        uid = (r.json()['msgs'])[0]['uid']
        print("获取到邮箱 {mail} 的内容uid: {uid}".format(mail=all, uid=uid))
    except Exception as e:
        print '[get box] {}'.format(e.message)
        pass

    GET_MESSAGE = 'https://getnada.com/api/v1/messages/html/'
    activ_code = ''
    try:
        r = requests.get(GET_MESSAGE + uid, headers=headers, proxies=proxies, timeout=600, verify=False)
        # text = r.json()['html']
        regex = r"\w{4}(?:-\w{4}){4}"
        activation_code = re.search(regex, r.content)
        activ_code = activation_code.group()
        print("Nessus 的激活码Activation code: {code}".format(code=activation_code.group()))
    except Exception as e:
        print '[get message] {}'.format(e.message)
        pass

    try:
        output = commands.getstatusoutput('/opt/nessus/sbin/nessuscli fetch --challenge')
        code = re.findall('Challenge code: (\w+)\n', output[1])
        challenge_code = code[0]
    except Exception as e:
        print '[-] {}'.format(e.message)

    headers["Content-Type"] = "application/x-www-form-urlencoded"
    resp = requests.post("https://plugins.nessus.org/v2/offline.php",
                         data="challenge={}&activation_code={}".format(challenge_code, activ_code),
                         headers=headers,
                         proxies=proxies,
                         timeout=600,
                         verify=False)
    url_link = re.findall('<a href="(.*?)" target="_blank">', resp.content)
    for pre_url in url_link:
        # if "mkconfig.php" in pre_url:
        #     url = "https://plugins.nessus.org/v2/" + pre_url
        #     file_name = "nessus.license"
        if "all-2.0.tar.gz" in pre_url:
            url = "https://plugins.nessus.org" + pre_url
            file_name = "all-2.0.tar.gz"
        elif "mkconfig.php" in pre_url:
            url = "https://plugins.nessus.org/v2/" + pre_url
            file_name = "nessus.license"
        else:
            continue
        cmd = 'wget "{}" -O {}'.format(url, file_name)
        print commands.getstatusoutput(cmd)[1]


def main(mode):
    if mode not in ["install", "update"]:
        print "unsupport mode"
        return
    print commands.getstatusoutput("service nessusd stop")[1]
    write_inc()
    get_plugin()

    if mode == "install":
        cmd_line = ['/opt/nessus/sbin/nessuscli fetch --register-offline nessus.license',
                    'echo "xxcdd\nxxcdd1996\nxxcdd1996\ny\n\ny\n" | /opt/nessus/sbin/nessuscli adduser',
                    'service nessusd start']

    elif mode == "update":
        cmd_line = [
            'rm -rf /opt/nessus/lib/nessus/plugins /opt/nessus/lib/nessus/plugins.bak',
            'rm -rf /opt/nessus/lib/nessus/plugins /opt/nessus/lib/nessus/plugins/plugins.bak',
            '/opt/nessus/sbin/nessuscli fetch --register-offline nessus.license',
            'service nessusd start']

    for i in cmd_line:
        print commands.getstatusoutput(i)[1]
    check_status()

    cmd_line = """service nessusd stop
            /opt/nessus/sbin/nessuscli update ./all-2.0.tar.gz > all-2.0.log
            echo '**********copy plugins';cp -r /opt/nessus/lib/nessus/plugins /opt/nessus/lib/nessus/plugins.bak
            chmod 777 plugin_feed_info.inc
            export new_PLUGIN_SET=$(cat all-2.0.log|tr -cd '0-9'|cut -c1-12);export old_PLUGIN_SET=$(cat plugin_feed_info.inc|tr -cd '0-9'|cut -c1-12);sed -i "s/$old_PLUGIN_SET/$new_PLUGIN_SET/g" plugin_feed_info.inc
            cp plugin_feed_info.inc /opt/nessus/lib/nessus/plugins/
            cp plugin_feed_info.inc /opt/nessus/var/nessus/
            service nessusd start"""

    for i in cmd_line.split('\n'):
        print commands.getstatusoutput(i)[1]

    check_status()

    cmd_line = """service nessusd stop
            cp -r /opt/nessus/lib/nessus/plugins.bak /opt/nessus/lib/nessus/plugins
            echo '**********copy plugins';cp plugin_feed_info.inc /opt/nessus/lib/nessus/plugins/
            cp plugin_feed_info.inc /opt/nessus/var/nessus/
            service nessusd start"""

    for i in cmd_line.split('\n'):
        print commands.getstatusoutput(i)[1]
    check_status()
    print commands.getstatusoutput("service nessusd stop")[1]


if __name__ == '__main__':
    if len(sys.argv) != 2:
        print "usage:\n    python {py} install\n    python {py} update".format(py='install.py')
    else:
        main(sys.argv[1])
