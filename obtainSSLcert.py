from socket import socket
from OpenSSL import SSL
from OpenSSL import crypto
import OpenSSL
from flask import Flask
import idna
from urllib import parse
import parser
import datetime
def get_certificate(hostname, port):
    sock = socket()
    # sock.settimeout(10) # 不要开启
    sock.setblocking(True) # 关键。。
    sock.connect((hostname, port), )
    ctx = SSL.Context(SSL.SSLv23_METHOD)
    ctx.check_hostname = False
    ctx.verify_mode = SSL.VERIFY_NONE

    sock_ssl = SSL.Connection(ctx, sock)
    sock_ssl.set_tlsext_host_name(idna.encode(hostname))  # 关键: 对应不同域名的证书
    sock_ssl.set_connect_state()
    sock_ssl.do_handshake()
    cert = sock_ssl.get_peer_certificate()
    sock_ssl.close()
    sock.close()
    return cert

def obtainSSLcert(domain):
    rs = parse.urlparse(domain)
    cert = get_certificate(rs.hostname, int(rs.port or 443))
    certIssue=cert.get_issuer()
    print("证书版本：\t",cert.get_version()+1)
    print("证书序列号：\t",hex(cert.get_serial_number()))
    print("使用的签名算法：\t",cert.get_signature_algorithm().decode("UTF-8"))
    print("颁发机构：\t",certIssue.commonName)
    datetime_struct=datetime.datetime.strptime(cert.get_notAfter().decode("UTF-8")[0:-2],"%Y%m%d%H%M%S")
    print("有效期从：\t",datetime_struct.strftime('%Y-%m-%d %H-%M-%S'))
    datetime_struct=datetime.datetime.strptime(cert.get_notBefore().decode("UTF-8")[0:-2],"%Y%m%d%H%M%S")
    print("到：\t",datetime_struct.strftime('%Y-%m-%d %H-%M-%S'))
    print("证书是否已经过期：\t",cert.has_expired())
    print("公钥：\n",crypto.dump_publickey(crypto.FILETYPE_PEM,cert.get_pubkey()).decode("utf-8"))
    print("主题信息：")
    print("CN：通用名称\tOU：机构单元名称\nO：机构名\tL：地理位置\nS：州/省名\tC：国名\n")
    for item in certIssue.get_components():
        print(item[0].decode("utf-8"),"——",item[1].decode("utf-8"))

if __name__=="__main__":
    obtainSSLcert("https://www.bilibili.com")
