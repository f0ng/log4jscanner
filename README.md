# 由于Python语言导致插件运行不是很顺畅，写了个Java版本的，移步至[log4j2burpscanner](https://github.com/f0ng/log4j2burpscanner)
# log4jscanner
log4j burp插件

![image](https://user-images.githubusercontent.com/48286013/145578008-bad6786a-d497-43a6-b7eb-bb41a975bda7.png)
![image](https://user-images.githubusercontent.com/48286013/145576830-0b835006-6974-47f6-9de2-bad8e37f6b84.png)

# 特点如下：
## 0x01 基于Cookie字段、XFF头字段、UA头字段发送payload
## 0x02 基于域名的唯一性，将host带入dnslog中
![image](https://user-images.githubusercontent.com/48286013/145577883-e0b6d506-5196-4edf-af76-8deaec8d57fc.png)

插件主要识别五种形式：

1.get请求，a=1&b=2&c=3  

2.post请求，a=1&b=2&c=3  

3.post请求，{“a”:”1”,”b”:”22222”}

4.post请求，a=1&param={“a”:”1”,”b”:”22222”}

5.post请求，{"params":{"a":"1","b":"22222"}}


# 免责声明
请勿将本项目技术或代码应用在恶意软件制作、软件著作权/知识产权盗取或不当牟利等非法用途中。实施上述行为或利用本项目对非自己著作权所有的程序进行数据嗅探将涉嫌违反《中华人民共和国刑法》第二百一十七条、第二百八十六条，《中华人民共和国网络安全法》《中华人民共和国计算机软件保护条例》等法律规定。本项目提及的技术仅可用于私人学习测试等合法场景中，任何不当利用该技术所造成的刑事、民事责任均与本项目作者无关。
