#!/usr/bin/env python3
from itertools import islice
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import subprocess, smtplib, re, time, os

#Timestamp variable
FROM="@domain.com"
TO=["@domain.com"]

def send_message(FROM_HDR, TO_HDR, message):
    server_out = smtplib.SMTP("email_server_address.int")
    server_out.ehlo()
    server_out.sendmail(FROM_HDR, TO_HDR, message.as_string())
    server_out.quit()

def compose_message(FROM, TO, NAME, line):
    msg=MIMEMultipart()
    msg['From']=FROM
    msg['To']=''.join(TO)
    msg['Subject']="[[AuditD-ALERT!]] Someone attempted to access the " + NAME + " file"
    body=line
    body=MIMEText(body)
    msg.attach(body)
    return msg

#Borrowed code from StackOverflow
def follow(auditlog):
    auditlog.seek(0, os.SEEK_END)
    while True:
        linef = auditlog.readline()
        if not linef:
            time.sleep(0.1)
            continue
        yield linef

def parse_out(name):
    timestamp=re.search(r'\w+\.\w+:\w+', line).group()
    epoch=re.split("\.", timestamp)
    converted=time.strftime('%Y/%m/%d %H:%M:%S', time.localtime(int(epoch[0])))
    newline=line.replace(epoch[0], str(converted))
    send_message(FROM, TO, compose_message(FROM, TO, name, newline))

##Main code
if __name__ == '__main__':
    logfile = open("/var/log/audit/audit.log", "r")
    loglines = follow(logfile)
    for line in loglines:
        all_lines = []
        if "shadow-access" in line and ("uid=1001" not in line):
            NAME="SHADOW"
            parse_out(name)
        elif "passwd-access" in line and "gid=0" not in line and("uid=1001" not in line):
            NAME="PASSWD"
            parse_out(name)
