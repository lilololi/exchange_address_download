#!/usr/bin/env python
#coding=utf-8

import httplib
import urllib
import re
import argparse


parser = argparse.ArgumentParser(description='Exchange_Address_Export.')
parser.add_argument('domain', type=str, help='website')
parser.add_argument('username', type=str, help='username')
parser.add_argument('password', type=str, help='password')
args = parser.parse_args()

headers = {
    'Accept': '*/*',
    'Referer': 'https://' + args.domain + '/owa/auth/logon.aspx?replaceCurrent=1&reason=2&url=https%3a%2f%2f' + args.domain + '%2fowa%2f',
    'Accept-Language': 'zh-CN',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0',
    'Connection': 'Keep-Alive',
    'Cache-Control': 'no-cache',
    'Cookie': '',
}


login_data = {
    'destination': 'https://%s/owa/' % args.domain,
    'flags': '0', 
    'forcedownlevel': '0',
    'trusted': '0',
    'username': args.username,
    'password': args.password,
    'isUtf8': '1', 
}

s = '<params><canary>%s</canary><St><ADVLVS sId="%s" mL="1" sC="52" sO="0" cki="%s" ckii="109" clcid="2052" cPfdDC="%s"/></St><SR>%d</SR><RC>50</RC></params>' 

def return_text(url,headers):
    conn = httplib.HTTPSConnection(args.domain)
    conn.request(method='GET', url=url,headers=headers)
    res =  conn.getresponse().read()
    conn.close()
    return res 

def getparams(fobj,canary):
    sCki=str(re.findall(r'sCki=\"\S*\"',fobj,re.I)[0]).replace('sCki="','').replace('"','') 
    sSid=str(re.findall(r'sSid=\"\S*\"',fobj,re.I)[0]).replace('sSid="','').replace('"','') 
    cPfdDC=str(re.findall(r'sPfdDC=\"\S*\"',fobj,re.I)[0]).replace('sPfdDC="','').replace('"','')
    return (canary,sSid,sCki,cPfdDC) 


def getMailAddFromFile(fobj):
    regex = re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,4}\b", re.IGNORECASE)
    mails = re.findall(regex, fobj)
    return set(mails)

try:

    #首次访问 获取Session ID
    conn = httplib.HTTPSConnection(args.domain)
    conn.request(method='GET', url='/owa/')
    res = dict(conn.getresponse().getheaders())
    session = res['set-cookie'].split(';')[0]   
    headers['Cookie'] = '%s; PBack=0' % session
    conn.close()

    #登录获取用户cookie  sessionid cadata
    conn = httplib.HTTPSConnection(args.domain)
    conn.request(method='POST', url='/owa/auth.owa', body=urllib.urlencode(login_data), headers=headers)
    res = dict(conn.getresponse().getheaders())
    session = res['set-cookie'].split(';') 
    #headers['Cookie'] += '; %s; %s' % (session[0],session[1].replace(' path=/, ',''))
    headers['Cookie'] += '; %s;' % session[0]
    conn.close()

    #登录获取用户cookie  UserContext tzid  owacsdc
    conn = httplib.HTTPSConnection(args.domain)
    conn.request(method='GET', url='/owa/',headers=headers)
    res = dict(conn.getresponse().getheaders())
    session = res['set-cookie'].split(';')    
    headers['Cookie'] += '; %s;%s;%s' % (session[0],session[2].replace('secure, ',''),session[4].replace('secure, ',''))
    conn.close()
    canary = session[0].replace('UserContext=','')
    headers['Cookie'] += '; MstrPgLd1=1; MstrPgLd2=1;'
    re1 = return_text('/owa/?ae=AddressList&t=Recipients',headers)
    SR ,flag ,count = 0,'',[]
    (canary,sSid,sCki,cPfdDC) = getparams(re1,canary)

    while True:
        m = s % (canary,sSid,sCki,cPfdDC,SR)
        conn = httplib.HTTPSConnection(args.domain)
        conn.request(method='POST', url='/owa/ev.owa?oeh=1&ns=DB&ev=LoadFresh', body=m, headers=headers)
        ar = getMailAddFromFile(conn.getresponse().read())
        print 'add item %d' % len(ar)
        count.extend(ar) 
        if flag == ar:
            break  
        conn.close()
        flag  =  ar
        SR += 50
    count = set(count)
    with open('%s.txt' % args.domain, 'a') as outFile:
        outFile.write("\n".join(count)+'\n')

except Exception, e:
    print 'Logon failure'

 
