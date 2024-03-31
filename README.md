In this protocol, the client and server never trust each other in key sharing. for this purpose there is the KDC - a seperate, remote server wich stores the long-term aes keys of the servers and clients on the network.

authentication is done using tickets, and aes session-keys are generated and encrypted by the KDC.

In this project, however - although we create and transmit authenticators, they serve no practical use - as the KDC consists of one single unit - differring form a real-world kerberos-system.

All the code here is implemented with python.

to run the client, server and kdc, simply run the client.py, msg_server.py or kdc.py respectively
