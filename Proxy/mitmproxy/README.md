# [mitmproxy](https://mitmproxy.org/)
mitmproxy用于配置内网机器通过代理机器访问到外网，实际实现原理类似进行中间人攻击（MITM），使用方式如下：
1. 从mitmproxy官网下载二进制文件，一般为一个压缩包；
2. 解压压缩包可以获得三个可执行文件：mitmdump、mitmproxy、mitmweb，它们的功能基本相同，仅交互方式略有不同，mitmdump提供一个类似tcpdump的界面，mitmweb提供一个网页交互页面，mitm提供一个交互式命令行界面，可以使用-p选项指定监听的端口；
3. 运行一次上述任意一个程序后会在~/.mitmproxy目录下生成签名文件，根据被代理机器所需，选择合适的签名文件安装即可正常进行代理，或者在被代理机器配置使用代理后访问<http://mitm.it/>获取相应教程；
4. 完成以上步骤后内网可正常访问外网，如需对流量进行筛选，可以使用python编写filter对http(s)等请求进行处理，详细编写方法即依赖包见[mitmproxy API文档](https://docs.mitmproxy.org/stable/api/events.html)，filter编写完成后可以在命令后添加-s选项指定要使用的filter文件。

filter示例代码：
```python
from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:
    # 禁止非https请求
    if flow.request.scheme != 'https':
        flow.response = http.Response.make(
            403,
            b"Only HTTPS is available.",
            {"Content-Type": "text/plain"}
        )
    # 禁止非GET方法
    elif flow.request.method != 'GET':
        flow.response = http.Response.make(
            403,
            b"Only GET is available.",
            {"Content-Type": "text/plain"}
        )
    # 禁止访问www.baidu.com
    elif flow.request.host == 'www.baidu.com':
        flow.response = http.Response.make(
            403,
            b"Can't view baidu",
            {"Content-Type": "text/plain"}
        )
```