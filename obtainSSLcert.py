from socket import socket
from OpenSSL import SSL
from OpenSSL import crypto
import OpenSSL
from flask import Flask
from flask.helpers import url_for
from flask import Flask, redirect, url_for, request
from flask.templating import render_template
import idna
from urllib import parse
import parser
import datetime
from werkzeug.utils import redirect

app=Flask(__name__)

@app.route('/index')
def index():
    return render_template("index.html")

@app.route('/certOutput')
def certOutput():
    with open("certSearch.txt","r") as f:
        domainDetail=f.read()
    return render_template("index.html",domainDetail=domainDetail)

@app.route('/search',methods=['POST'])
def requestDomainSearch():
    domain=request.form['domain']
    return redirect(url_for('obtainSSLcert',domain=domain))

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

@app.route('/cert/<path:domain>')
def obtainSSLcert(domain):
    rs = parse.urlparse(domain)
    cert = get_certificate(rs.hostname, int(rs.port or 443))
    certIssue=cert.get_issuer()
    output=""
    datetime_struct=datetime.datetime.strptime(cert.get_notAfter().decode("UTF-8")[0:-2],"%Y%m%d%H%M%S")
    datetime_struct=datetime.datetime.strptime(cert.get_notBefore().decode("UTF-8")[0:-2],"%Y%m%d%H%M%S")
    output+=("证书版本：\t"+str(cert.get_version()+1)+'\n')
    output+=("证书序列号：\t"+str(hex(cert.get_serial_number()))+'\n')
    output+=("使用的签名算法：\t"+str(cert.get_signature_algorithm().decode("UTF-8"))+'\n')
    output+=("颁发机构：\t"+str(certIssue.commonName)+'\n')
    output+=("有效期从：\t"+datetime_struct.strftime('%Y-%m-%d %H-%M-%S')+'\n')
    output+=("到：\t"+datetime_struct.strftime('%Y-%m-%d %H-%M-%S')+'\n')
    output+=("证书是否已经过期：\t"+str(cert.has_expired())+'\n')
    output+=("公钥：\n"+crypto.dump_publickey(crypto.FILETYPE_PEM,cert.get_pubkey()).decode("utf-8")+'\n')
    output+=("主题信息：\n")
    output+=("CN：通用名称\tOU：机构单元名称\nO：机构名\tL：地理位置\nS：州/省名\tC：国名\n")
    for item in certIssue.get_components():
        output+=(item[0].decode("utf-8")+"——"+item[1].decode("utf-8")+'\n')
    with open("certSearch.txt","w") as f:
        f.write(output)
    return render_template("index.html",certDetail=output)
    # return redirect(url_for("certOutput"))

if __name__=="__main__":
    app.run(debug=True)
