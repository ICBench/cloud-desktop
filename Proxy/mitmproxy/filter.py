from mitmproxy import http
from tld import get_fld

fldList=[
    "github.com",
    "aliyuncs.com"
]

def checkFld(fld: str)->bool:
    for allowedFld in fldList:
        if allowedFld==fld:
            return True
    return False

def request(flow: http.HTTPFlow)->None:
    url=flow.request.url
    fld=get_fld(url)
    contentType=flow.request.headers.get("content-type")
    method=flow.request.method
    if method!="GET" and not (method=="POST" and contentType=="application/x-git-upload-pack-request"):
        flow.response = http.Response.make(
            403,
            b"Method is forbidden.",
            {"Content-Type": "text/plain"}
        )
    if not checkFld(fld):
        flow.response = http.Response.make(
            403,
            f"{url} is forbidden.",
            {"Content-Type": "text/plain"}
        )