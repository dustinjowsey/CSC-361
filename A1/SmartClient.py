from http.client import HTTP_PORT
import socket
from sqlite3 import connect
import ssl
import re
import time
import os
import sys
import select
import threading


def main(argv):
    if(len(argv) > 1):
        print("Too many arguments. Try running like 'python SmartClient.py <URL of server>'")
        exit()
    elif(len(argv) < 1):
        print("Too few arguments. Need a URL to send a request to. Try running like 'python SmartClient.py <URL of server>'")
        exit()

    data = send_request(argv[0])
    #rcode = data[0]
    #data = data[1]

    port = 443 #default port for ssl

    check_http2 = ssl.create_default_context()
    check_http2.set_alpn_protocols(["h2", "http/1.1"])
    supports_http2 = check_http2.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=argv[0])
    supports_http2.connect((argv[0], port))

    print("\n---Response body---")
    print(f"website: {argv[0]}")
    print(f"1. Supports http2: {supports_http2.selected_alpn_protocol()}")
    print("2. List of Cookies:")
    for line in data:
        if re.search("^Set-Cookie: ", line):
            temp = line.split("=", 2)
            cinfo = "cookie name: " + temp[0][12:]
            if re.search("expires=", line):
                temp = line.split(";")
                for word in temp:
                    if re.search("expires=", word):
                        temp = word
                        break
                cinfo = cinfo + ", expires time: " + word[9:]
            if re.search("domain=", line):
                temp = line.split(";")
                for word in temp:
                    if re.search("domain=", word):
                        temp = word
                        break
                cinfo = cinfo + ", domain name: " + word[8:]
            print(cinfo)
    print("Password-protected: ")


#Sends HTTP request to the provided url and returns the response code
def send_request(url, port=80): #Defualt port for HTTP
    print("---Request begin---")
    print(f"GET http://{url}/index.html HTTP/1.1")
    print(f"Host: {url}")
    print("Connection: Keep-Alive")

    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((socket.gethostbyname(f"{url}"), port))
    request = f"GET /index.html HTTP/1.1\r\nHost: {url}\r\nConnection: Keep-Alive\r\n\r\n"
    client.send(request.encode())
    print("\n---Request end---\nHTTP request sent, awaiting response...\n")
    data = client.recv(1024)

    print("---Response header---")
    print(data.decode())


    data = data.decode().splitlines()
    for line in data:
        if re.search("^HTTP", line):
            rcode = line.split(" ", 2)[1]
            break
    
    if int(rcode) >= 300 and int(rcode) <= 399:
        for line in data:
            if re.search("^Location: ", line):
                url = line.split(" ", 1)[1].split("/", 3)[2]
                print(url)
                https_request(url)
                break
    return (rcode, data)
    #return(data)

def https_request(url, port=443): #default port for ssl (https)
    print("---Request begin---")
    print(f"GET https://{url}/index.html HTTP/2")
    print(f"Host: {url}")
    print("Connection: Keep-Alive")

    client =  ssl.
    client = ssl.create_default_context()
    client.set_alpn_protocols(["h2", "http/1.1"])
    client = client.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=url)
    client.connect((url, port))
    request = f"GET /index.html HTTP/2\r\nHost: {url}\r\nConnection: Keep-Alive\r\n\r\n"
    client.send(request.encode())
    print("\n---Request end---\nHTTPS request sent, awaiting response...\n")
    data = client.recv(1024)
    print("---Response header---")
    print(data.decode())



if __name__ == "__main__":
    main(sys.argv[1:])