# CSC-361 Assignment 1
To run:
python SmartClient.py <URI>

URI format:
1. <protocal>://<host>[:<port>]/<filepath>
	a. must be in this format. SmartClient requires you to provide "://"
	   if you provide a protocal.
	b. To provide a port you must add "[:]" characters similar to the above format
	c. To provide a filepath you must add "/" either after the port if provided 
           or after the host if no port is provided.
2. SmartClient can parse most URI's into protocol, host, port, filepath
	a. The only mandatory part of the URI is the host. SmartClient 
	   will default to 'http' and filepath 'index.html'
	b. Note SmartClient will not validate the port number.
	   If you provide protocol http and pass port number 443 SmartClient 
           will return an error.

Example URI inputs:
	1. www.uvic.ca
	2. https://www.uvic.ca
	3. https://www.uvic.ca/index.html
	4. https://www.uvic.ca[:443]/index.html
	5. www.uvic.ca[:80]/index.html
		a. Remeber that SmartClient defaults to http protocal (i.e be careful of the provided port number)
	6. www.uvic.ca[:80]
