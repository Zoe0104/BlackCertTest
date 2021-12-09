import os
import pickle
from socket import socket
from sys import path
import time
from OpenSSL import SSL
from OpenSSL import crypto
import OpenSSL
from flask import Flask, json,jsonify,send_file
from flask.helpers import flash, url_for
from flask import Flask, redirect, url_for, request
from flask.templating import render_template
import idna
from urllib import parse
import parser
import datetime
import sklearn
from werkzeug.utils import secure_filename
from scipy.sparse.construct import rand, vstack
from sklearn import svm
from sklearn.ensemble import VotingClassifier
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model  import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score,precision_score,recall_score
import pickle
import numpy as np


app=Flask(__name__)
CURRENT_PARENT=os.path.dirname(__file__)
UPLOAD_FOLDER = CURRENT_PARENT+'\\uploadCert'  #文件存放路径
ALLOWED_EXTENSIONS = set(['crt','cer','pem']) #限制上传文件格式
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

# 首页
@app.route('/index')
def index():
    return render_template("index.html")

##############第一部分 网站证书查询###################
@app.route('/search',methods=['GET'])
def requestDomainSearch():
    domain=request.args.get("domain","",type=str)
    try:
        return jsonify(output=obtainSSLcert(domain),state=1)
    except TimeoutError:
        return jsonify(output="请检查该域名是否无法访问。",state=0)
    except Exception:
        return jsonify(output="请输入以\"https://\"开头的正确格式的域名。",state=0)

# 获取证书文件
def get_certificate(hostname, port):
    sock = socket()
    # sock.settimeout(10) # 不要开启
    sock.setblocking(True) # 关键。。
    sock.connect((hostname, port), )   #无法连接国内上不去的网站
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

# 存储证书文件并分析内容
def obtainSSLcert(domain):
    rs = parse.urlparse(domain)
    cert = get_certificate(rs.hostname, int(rs.port or 443))
    with open("cert.pem","wb") as f:
        # 别再查怎么存证书了，这不就是吗
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM,cert))

    certIssue=cert.get_issuer()
    certSubject=cert.get_subject()
    output=""
    datetime_struct=datetime.datetime.strptime(cert.get_notAfter().decode("UTF-8")[0:-2],"%Y%m%d%H%M%S")
    datetime_struct=datetime.datetime.strptime(cert.get_notBefore().decode("UTF-8")[0:-2],"%Y%m%d%H%M%S")
    output+=("主题信息：\n")
    output+=("CN：通用名称\tOU：机构单元名称\tO：机构名\nL：地理位置\tS：州/省名\tC：国名\n")
    for item in certSubject.get_components():
        output+=(item[0].decode("utf-8")+"——"+item[1].decode("utf-8")+'\n')
    output+=("-------------------\n")
    output+=("证书版本：\t"+str(cert.get_version()+1)+'\n')
    output+=("证书序列号：\t"+str(hex(cert.get_serial_number()))+'\n')
    output+=("使用的签名算法：\t"+str(cert.get_signature_algorithm().decode("UTF-8"))+'\n')
    output+=("颁发机构：\t"+str(certIssue.commonName)+'\n')
    output+=("有效期从：\t"+datetime_struct.strftime('%Y-%m-%d %H-%M-%S')+'\n')
    output+=("至：\t"+datetime_struct.strftime('%Y-%m-%d %H-%M-%S')+'\n')
    output+=("证书是否已经过期：\t"+str(cert.has_expired())+'\n')
    output+=("公钥：\n"+crypto.dump_publickey(crypto.FILETYPE_PEM,cert.get_pubkey()).decode("utf-8")+'\n')
    
    return output

# 下载证书文件
@app.route('/download')
def download():
    return send_file("cert.pem")

######################第二部分 恶意证书检测#####################

# 检查上传的文件是否符合文件类型
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# 通过特征工程提取的特征
def extractFeature(cert):
    cert_feature=[]
    #1 输入是否自签
    a=cert.get_extension_count()
    for i in range(0,a):
        b=cert.get_extension(i).get_short_name()
        if b==b'basicConstraints' and cert.get_extension(i).get_data()==b'0\x03\x01\x01\xff':
            cert_feature+=[1]
        else:
            cert_feature+=[0]

    #2 输入是否有效域名
    a=cert.get_subject().CN
    if not(a==None or a=="example.com"):
        x=len(str.split(a,"."))
        if x>=2 and x<=3:
            cert_feature+=[1]
        else:
            cert_feature+=[0]
    else:
        cert_feature+=[0]

    #3 输入是否是可疑的country
    subject=cert.get_subject()
    if subject.countryName==None:
        # c字段不存在就当做不可疑
        cert_feature+=[0]
    else:
        if len(subject.countryName)<2 or len(subject.countryName)>2:
            cert_feature+=[1]
        elif subject.countryName[0]==subject.countryName[1] or (subject.countryName[0]<'A' or subject.countryName[0]>'Z'):
            cert_feature+=[1]
        else:
            cert_feature+=[0]
    
    issuer=cert.get_issuer()
    if issuer.countryName==None:
        cert_feature+=[0]
    else:
        if len(issuer.countryName)<2 or len(issuer.countryName)>2:
            cert_feature+=[1]
        elif issuer.countryName[0]==issuer.countryName[1] or (issuer.countryName[0]<'A' or issuer.countryName[0]>'Z'):
            cert_feature+=[1]
        else:
            cert_feature+=[0]

    #4 输入是否subject各字段存在
    tem_dict={b'C':None,b'O':None,b'OU':None,b'L':None,b'ST':None,b'CN':None,b'emailAddress':None}
    for i in cert.get_subject().get_components():
        if i[0] in tem_dict.keys():
            tem_dict[i[0]]=i[1]
    for each in tem_dict.items():
        if each[1]!=None:
            cert_feature+=[1]
        else:
            cert_feature+=[0]

    #5 输入是否issuer各字段存在
    tem_dict={b'C':None,b'O':None,b'OU':None,b'L':None,b'ST':None,b'CN':None,b'emailAddress':None}
    for i in cert.get_issuer().get_components():
        if i[0] in tem_dict.keys():
            tem_dict[i[0]]=i[1]
    for each in tem_dict.items():
        if each[1]!=None:
            cert_feature+=[1]
        else:
            cert_feature+=[0]

    #6 subject、issuer和extension的item个数
    cert_feature+=[len(cert.get_subject().get_components())]
    cert_feature+=[len(cert.get_issuer().get_components())]
    cert_feature+=[cert.get_extension_count()]

    #7 有效期长度
    validate_beg=str(cert.get_notBefore(),encoding="utf-8")
    validate_end=str(cert.get_notAfter(),encoding="utf-8")
    if len(validate_beg)!=len("20191201002241Z") or len(validate_end)!=len("20191201002241Z"):
        cert_feature+=[-1]
    elif (not str.isdigit(validate_beg[0:-1])) or (not str.isdigit(validate_end[0:-1])):
        cert_feature+=[-1]
    else:
        validate_beg=validate_beg[0:-1]
        validate_end=validate_end[0:-1]
        try:
            beginArray=time.strptime(validate_beg,"%Y%m%d%H%M%S")
            begin=time.mktime(beginArray)
            endArray=time.strptime(validate_end,"%Y%m%d%H%M%S")
            end=time.mktime(endArray)
        except OverflowError:
            cert_feature+=[-1]
        else:
            if end-begin<=0:
                cert_feature+=[-1]
            else:
                cert_feature+=[(end-begin)]
        return cert_feature

@app.route('/analysis', methods=['GET', 'POST'])
def analysisCert():
    if request.method == 'POST':
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return jsonify(state=0)
        file = request.files['file']
        # if user does not select file, browser also
        # submit an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return jsonify(state=0)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
    else:
        return jsonify(state=0)
    
    cert_file_buffer=open(os.path.join(app.config['UPLOAD_FOLDER'], filename)).read()
    cert=crypto.load_certificate(crypto.FILETYPE_PEM,cert_file_buffer)
    cert_feature=extractFeature(cert) # 获取特征工程的特征
    # 加载分类器进行分类
    with open(os.path.join(CURRENT_PARENT,"classific_model\\adaBoost.pickle"),"rb") as f:
        ada_module=pickle.load(f)
    y=ada_module.predict([cert_feature])# 特征数量和模型的特征数量不匹配，可能是得重新训练一下模型就是说
    if y==1:
        return jsonify(message="这个证书很安全！",state=1)
    else:
        return jsonify(message="这个证书很可疑！",state=1)

if __name__=="__main__":
    app.run(debug=True)
