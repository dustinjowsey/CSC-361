#from asyncio import protocols
import errno
from fileinput import filename
#from http.client import HTTP_PORT
from posixpath import split
import socket
from sqlite3 import connect
import ssl
import re
import time
import os
import sys
import select
import threading
#from typing import Protocol

def main(argv):
    if(len(argv) > 1):
        print("Too many arguments. Try running like 'python SmartClient.py <URI of server>'")
        exit()
    elif(len(argv) < 1):
        print("Too few arguments. Need a URL to send a request to. Try running like 'python SmartClient.py <URI of server>'")
        exit()

    data = split_URI(argv[0])
    
    rcode = data[0]
    data = data[1]
    #check if webpage moved if so send request to new address
    while int(rcode) == 302 or int(rcode) == 301:
        for line in data:
            if re.search("^Location: ", line) or re.search("<a href=", line):
                if re.search("^Location: ", line):
                    URI = line.split(" ", 1)[1]
                elif re.search(r"<a href=", line):
                    URI = line.split("\"", 3)[1]
                else:
                    print("***Error finding moved URI***")
                    exit()
                data = split_URI(URI)
                rcode = data[0]
                data = data[1]
                break
    print("Finished!")

#Based on the info provided in the URI extracts protocol, host, port, filepath if provided
def split_URI(URI, send_request = True):
    request_data = {}
    protocol = None
    port = None
    filepath = None
    if re.search(r"://", URI) != None:
        protocol = URI.split(":", 1)[0]
        request_data["protocol"] = protocol
    if protocol == None:
        host = re.split("/", URI)[0]
        request_data["host"] = host
    else:
        host = URI.split("//", 1)[1]
        request_data["host"] = host
    if re.search("\[:\d*\]", host):
        port = re.search("\[:\d*\]", host).group(0)
        host = re.split("\[", host)[0]
        request_data["host"] = host
        request_data["port"] = re.split(":", port)[1].split("]")[0]
    if protocol == None:
        if re.search("/", URI) != None:
            filepath = URI.split("/", 1)
            request_data["filepath"] = filepath[1]
            if port == None:
                request_data["host"] = filepath[0]
    else:
        filepath = URI.split("/", 3)
        if port == None:
            request_data["host"] = filepath[2]
        if len(filepath) == 4:
            filepath = filepath[3]
            request_data["filepath"] = filepath
        else:
            filepath = None

    if host == None:
        print("***Error could not gather host name from provided URI***")
        exit()

    if send_request == True:
        return request_to_send(request_data)
    else:
        return(protocol, host, port, filepath)

#Must be called after parsing URI!
#Determines what data was provided in the URI so we can set defaults when sending a request if needed
def request_to_send(data):
        if all (key in data for key in ("protocol", "host", "port", "filepath")):
            return send_request(data["protocol"], data["host"], data["port"], data["filepath"])
        elif all (key in data for key in ("host", "port", "filepath")):
            return send_request(host=data["host"], port=data["port"], filepath=data["filepath"])
        elif all (key in data for key in ("protocol", "host", "filepath")):
            return send_request(data["protocol"], data["host"], filepath=data["filepath"])
        elif all (key in data for key in ("protocol", "host")):
            return send_request(data["protocol"], data["host"])
        elif all (key in data for key in ("host", "port")):
            return send_request(host=data["host"], port=data["port"])
        elif all (key in data for key in ("host", "filepath")):
            return send_request(host=data["host"], filepath=data["filepath"])
        else:
            return send_request(host=data["host"])
    #Created a match statement, but linux servers aren't running python 3.10. Match statement would be much more elegant
    #match data:
    #    case {"protocol":protocol, "host":host, "port":port, "filepath":filepath}:
    #        return send_request(protocol, host, port, filepath)
    #    case {"host":host, "port":port, "filepath":filepath}:
    #        return send_request(host=host, port=port, filepath=filepath)
    #    case {"protocol":protocol, "host":host, "filepath":filepath}:
    #        return send_request(protocol, host, filepath=filepath)
    #    case {"protocol":protocol, "host":host}:
    #        return send_request(protocol, host)
    #    case {"host":host, "port":port}:
    #        return send_request(host=host, port=port)
    #    case {"host":host, "filepath":filepath}:
    #        return send_request(host=host, filepath=filepath)
    #    case {"host":host}:
    #        return send_request(host=host)

#Sends HTTP request to the provided url and returns the response code
def send_request(protocol="http", host=None, port=80, filepath="index.html"): #Defualt port for HTTP
    try:
        if protocol == "http":
            client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
            client = ssl.create_default_context()
            client = client.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
            port=443 #default port for ssl
        client.connect((socket.gethostbyname(str(host)), int(port)))
    except:
        print("***Error creating client socket or connecting to web server. Check URI/URL and/or internet connection***")
        exit()

    request = "GET /"+filepath+" HTTP/1.1\r\nHost:"+host+"\r\nConnection: Keep-Alive\r\n\r\n"
    
    print("---Request begin---")
    print("GET "+protocol+"://"+host+"[:"+str(port)+"]/"+filepath+" HTTP/1.1")
    print("Host: "+host)
    print("Connection: Keep-Alive")
    
    client.send(request.encode())
    print("\n---Request end---\nHTTP request sent, awaiting response...\n")

    data = client.recv(1024)
    if data == None:
        print("***Error recieving info from server! Possibly a timeout?***")
        exit()
    
    if(data == None):
        print("***No data read***")
        exit()

    print("---Response header---")
    print(data.decode())

    rcode = None
    data = data.decode().splitlines()
    for line in data:
        if re.search("^HTTP", line):
            rcode = line.split(" ", 3)[1]
            break

    if rcode == None:
        print("***Error getting return code, cannot process response***")
        exit()

    password_protected = "no"
    if int(rcode) == 401:
        password_protected = "yes"
    if int(rcode) == 404:
        print("***Error page could not be found***")
        exit()

    ssl_port = 443
    #checking if url supports http2
    check_http2 = ssl.create_default_context()
    check_http2.set_alpn_protocols(["h2"])
    supports_http2 = "no"
    try:
        check_http2 = check_http2.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=host)
        check_http2.connect((host, ssl_port))
        check_http2.do_handshake()
        if check_http2.selected_alpn_protocol() == "h2":
            supports_http2 = "yes"
    except:
        print("***Error creating socket and checking HTTP/2.0 support. Defualting to no***")

    print("\n---Response body---")
    print("website: "+host)
    print("1. Supports http2: "+supports_http2)
    print("2. List of Cookies:")
    for line in data:
        if re.search("^Set-Cookie: ", line):
            temp = line.split("=", 2)
            cinfo = "cookie name: " + temp[0][12:]
            if re.search("[eE]xpires=", line):
                temp = line.split(";")
                for word in temp:
                    if re.search("[eE]xpires=", word):
                        temp = word
                        break
                cinfo = cinfo + ", expires time: " + word[9:]
            if re.search("[dD]omain=", line):
                temp = line.split(";")
                for word in temp:
                    if re.search("[dD]omain=", word):
                        temp = word
                        break
                cinfo = cinfo + ", domain name: " + word[8:]
            print(cinfo)
    print("Password-protected: "+password_protected)
    return  (rcode, data)

if __name__ == "__main__":
    main(sys.argv[1:])
