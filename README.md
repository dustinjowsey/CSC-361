# CSC-361 Assignment 1
To run:
python SmartClient.py <URI>

URI format:     
-\<protocal>://\<host>\[:\<port>\]/\<filepath>     
    - must be in this format. SmartClient requires you to provide "://" if you provide a protocal.
    - To provide a port you must add "\[:\]" characters similar to the above format
    - To provide a filepath you must add "/" either after the port if provided or after the host if no port is provided.
- SmartClient can parse most URI's into protocol, host, port, filepath
    - The only mandatory part of the URI is the host. SmartClient will default to 'http' and filepath 'index.html'
    - Note SmartClient will not validate the port number. If you provide protocol http and pass port number 443 SmartClient will return an error.
      
Example URI inputs:
- www.uvic.ca
- https://www.uvic.ca
- https://www.uvic.ca/index.html
- https://www.uvic.ca[:443]/index.html
- www.uvic.ca[:80]/index.html
    - Remeber that SmartClient defaults to http protocal (i.e be careful of the provided port number)
- www.uvic.ca[:80]
