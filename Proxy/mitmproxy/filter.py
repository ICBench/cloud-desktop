from mitmproxy import http
from tld import get_fld

fldList=[
    "github.com",
]

def checkFld(fld: str)->bool:
    for allowedFld in fldList:
        if allowedFld==fld:
            return True
    return False

def request(flow: http.HTTPFlow)->None:
    scheme=flow.request.scheme
    host=flow.request.host
    contentType=flow.request.headers.get("content-type")
    method=flow.request.method
    if scheme!="https":
        flow.response = http.Response.make(
            403,
            b"Only HTTPS is available.",
            {"Content-Type": "text/plain"}
        )
    if method!="GET" and not (method=="POST" and contentType=="application/x-git-upload-pack-request"):
        flow.response = http.Response.make(
            403,
            b"Method is forbidden.",
            {"Content-Type": "text/plain"}
        )
    fld=get_fld("https://"+host)
    if checkFld(fld):
        flow.response = http.Response.make(
            403,
            f"{host} is forbidden.",
            {"Content-Type": "text/plain"}
        )