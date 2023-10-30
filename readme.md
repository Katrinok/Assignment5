# Conputer Networking -- The Botnet saves the world

**Group 20**

_Project members:_
In this project we create a server on skel and try to connect to all servers in the network createing a network of connected servers. We also create a client that can connects to the server we created  and send messages to other clients connected to the server.

_Pre-requisites:_

- have c++ installed on your computer
- have a terminal that can run c++ programs or a c++ IDE such as VScode

## How to run the program

1. be in the directory where the files are located
2. run the command `make` to compile the files
3. run the command `./tsampgroup20 <port>` to run the server. You can choose any port from the range 4000-4100 if they are available.
4. To run the client run the command `./chat_client <server_ip> <server_port>` where the server_ip is the ip address of the server and server_port is the port the server is running on.

## How to use the program

When the server and client is up and running you can send commands to the server and said server can use those commands to send messages to other clients connected to the server. The commands are listed below.

## Server commands:

The server commands are commands that the server can use to send messages to other servers/clients connected to the server.

1. QUERYSERVERS, <GroupId> or <GroupId> <ServerIp> <ServerPort>: 
    Immediately send QUERYSERVERS to a new connection

    If QUERYSERVERS command is received, respond with SERVERS, a list of all servers connected to this server, the first server 

2. SERVERS, <GroupId> <ServerIp> <ServerPort> <ServerIp> <ServerPort> ...: 
    Respond to a QUERYSERVERS command with a list of all servers connected to this server, the first server in the list is the server that sent the QUERYSERVERS command.

3. SENDMSG, <GroupId> <Message>: 
    Send a message to all servers in the group with the specified group id. If the group id is unknown to the server, the server will store the message

4. FETCH_MSGS, <GroupId>: 
    Send all stored messages for the specified group id to the server that sent the FETCH_MSGS command. If the group id is unknown to the server, the server will respond with an empty message.

5. STATUSREQ <GroupId>: 
    Send a STATUSRESP to the server that sent the STATUSREQ command. The STATUSRESP should contain the number of messages stored for the specified group id.

6. STATUSRESP <GroupId> <NumberOfMessages>:

## Client commands:

1. CONNECT <name>: /tsampgroup12 <port> 4066
    Registers the client with a specified name.
2. LEAVE: 
    Disconnects the client from the server.
3. WHO: 
    Asks the server to return a list of connected clients.
4. MSG ALL <message>: 
    Sends a message to all connected clients.
5. MSG <client_name> <message>: 
    Sends a message to a specific client.