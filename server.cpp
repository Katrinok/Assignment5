//
// Simple chat server for TSAM-409
//
// Command line: ./chat_server 4000 
//
// Author: Jacky Mallett (jacky@ru.is)
//
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <string.h>
#include <algorithm>
#include <map>
#include <vector>
#include <list>

#include <iostream>
#include <sstream>
#include <thread>
#include <map>
#include <arpa/inet.h>
#include <regex>
#include <cstring> // For memset()

#include <unistd.h>

// fix SOCK_NONBLOCK for OSX
#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#define BACKLOG  5          // Allowed length of queue of waiting connections

struct myServer {
    std::string ip_address;
    int port;


    // Constructor
    myServer(const std::string& ip, int p) : ip_address(ip), port(p) {}
};

// Simple class for handling connections from clients.
//
// Client(int socket) - socket to send/receive traffic from client.
class Client {
    public:
    int sock;              // socket of client connection
    std::string name;           // Limit length of name of client's user

    Client(int socket) : sock(socket){} 

    ~Client(){}            // Virtual destructor defined for base class
};

// A class Server to represent all connected servers
class Server {
    public:
    std::string groupID;
    std::string ip_address;
    int port;

    Server(const std::string& _groupID, const std::string& _ip, int _port)
        : groupID(_groupID),ip_address(_ip),port(_port) {}

    friend std::ostream& operator<<(std::ostream& os, const Server& server); // to use '<<' to send a Server object to an 'std::ostream', like std::out
};

std::ostream& operator<<(std::ostream& os, const Server& server)
{
    os << server.groupID << "," << server.ip_address << "," << server.port; // server obj as GROUP_ID,IP,Port
    return os;
}

// Note: map is not necessarily the most efficient method to use here,
// especially for a server with large numbers of simulataneous connections,
// where performance is also expected to be an issue.
//
// Quite often a simple array can be used as a lookup table, 
// (indexed on socket no.) sacrificing memory for speed.

std::map<int, Client*> clients; // Lookup table for per Client information
std::vector<Server> connectedServers; // A global list of servers

// Open socket for specified port.
//
// Returns -1 if unable to create the socket for any reason.

int open_socket(int portno) {
        struct sockaddr_in sk_addr;   // address settings for bind()
        int sock;                     // socket opened for this port
        int set = 1;                  // for setsockopt

        // Create socket for connection. Set to be non-blocking, so recv will
        // return immediately if there isn't anything waiting to be read.
    #ifdef __APPLE__     
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Failed to open socket");
        return(-1);
    } 
    #else
    if((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0) {
        perror("Failed to open socket");
        return(-1);
    }
    #endif

    // Turn on SO_REUSEADDR to allow socket to be quickly reused after 
    // program exit.

    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &set, sizeof(set)) < 0) {
        perror("Failed to set SO_REUSEADDR:");
    }
    set = 1;
    #ifdef __APPLE__     
    if(setsockopt(sock, SOL_SOCKET, SOCK_NONBLOCK, &set, sizeof(set)) < 0) {
        perror("Failed to set SOCK_NOBBLOCK");
    }
    #endif
    memset(&sk_addr, 0, sizeof(sk_addr));

    sk_addr.sin_family      = AF_INET;
    sk_addr.sin_addr.s_addr = inet_addr("130.208.243.61"); // laga seinna
    sk_addr.sin_port        = htons(portno);

    // Bind to socket to listen for connections from clients

    if(bind(sock, (struct sockaddr *)&sk_addr, sizeof(sk_addr)) < 0) {
        perror("Failed to bind to socket:");
        return(-1);
    } else {
        return(sock);
    }
}

// Close a client's connection, remove it from the client list, and
// tidy up select sockets afterwards.

void closeClient(int clientSocket, fd_set *openSockets, int *maxfds) {

    printf("Client closed connection: %d\n", clientSocket);

    // If this client's socket is maxfds then the next lowest
    // one has to be determined. Socket fd's can be reused by the Kernel,
    // so there aren't any nice ways to do this.

    close(clientSocket);      

    if(*maxfds == clientSocket) {
        for(auto const& p : clients) {
            *maxfds = std::max(*maxfds, p.second->sock);
        }
    }

    // And remove from the list of open sockets.

    FD_CLR(clientSocket, openSockets);

}

// Process command from client on the server

// A function that makes the server connect to another server
int connectToServer(const std::string& ip_address, int port, std::string groupID, myServer myServer) {
    int serverSock;
    struct sockaddr_in serverAddr;

    serverSock = socket(AF_INET, SOCK_STREAM, 0);
    if(serverSock < 0) {
        perror("Error opening socket");
        return -1;
    }

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);

    if(inet_pton(AF_INET, ip_address.c_str(), &serverAddr.sin_addr) <= 0) {
        perror("Error converting IP address");
        return -1;
    }

    if(connect(serverSock, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        perror("Error connecting to server");
        return -1;
    }

    printf("Connected to server at %s:%d\n", ip_address.c_str(), port);


    // Here send QUERYSERVER
    std::string message = "QUERYSERVERS," + groupID;
    if(send(serverSock, message.c_str(), message.length(), 0) < 0) {
        perror("Error sending QUERYSERVERS message");
    }
    std::cout << "QUERYSERVERS sent" << message << std::endl;

    // Now get the response from the other server
    // Wait for a response from the server after sending the message
    char responseBuffer[1025]; // Buffer to hold the response
    memset(responseBuffer, 0, sizeof(responseBuffer)); // Clear the buffer

    int bytesRead = recv(serverSock, responseBuffer, sizeof(responseBuffer)-1, 0); // Receive the data
    if(bytesRead < 0) {
        perror("Error receiving response from server");
        close(serverSock);
        return -1;
    }
    else if(bytesRead == 0) {
        std::cout << "Server closed connection after sending QUERYSERVERS" << std::endl;
        close(serverSock);
        return -1;
    }
    else {
        std::cout << "Received response after QUERYSERVERS: " << responseBuffer << std::endl;
    }
    
    // Now the response should be QUERYSERVERS,GROUP_ID and we want to extract the group id 
    
    std::string receivedResponse = responseBuffer;   // Convert char array to string
    size_t startPos = receivedResponse.find(",");    // Find position of the first comma
    std::string receivedGroupID = receivedResponse.substr(startPos + 1);  // Extract group ID

    // Then add the server to connected servers
    Server newServer(receivedGroupID, ip_address, port);
    connectedServers.push_back(newServer);

    std::cout << "Server list" << std::endl; //DEBUG
    for(const auto& server : connectedServers) {
        std::cout << server << std::endl;
    }


    // Now respond with a string on the format QUERYSERVERS,FROM_GROUP_ID,FROM_IP_ADDRESS,FROM_PORT,<connected servers group id, ip, and port>
    std::string queryservers = QueryserversResponse(groupID, myServer); 

    if(send(serverSock, queryservers.c_str(), queryservers.length(), 0) < 0) {
        perror("Error sending SERVERS message");
    }
    std::cout << "SERVERS sent" << queryservers << std::endl; //DEBUG

    return serverSock;
}

std::string QueryserversResponse(const std::string& fromgroupID, myServer myServer)
{
    std::string response = "SERVERS," + fromgroupID + "," + myServer.ip_address + "," + std::to_string(myServer.port) + ";"; // Should get the info for this server P3_GROUP_20,130.208.243.61,Port

    for(const auto& server : connectedServers) {
        response += server.groupID + "," + server.ip_address + "," + std::to_string(server.port) + ";";
    }

    return response;
}


// Hér þarf að bæta við commandum 
// GETMSG, GROUP ID Get a single message from the server for the GROUP ID
// SENDMSG,GROUP ID,<message contents> Send a message to the server for the GROUP ID
// LISTSERVERS List servers your server is connected to

void clientCommand(int clientSocket, fd_set *openSockets, int *maxfds, 
                  char *buffer, std::string groupID, myServer Server) {
    std::vector<std::string> tokens;
    std::string token;

    // Split command from client into tokens for parsing
    std::stringstream stream(buffer);

    while(stream >> token)
        tokens.push_back(token);

    if((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 2)) { // IP og port spurning um að bua til struct setja inn allar uppl 
        clients[clientSocket]->name = tokens[1]; // name format    
    }
    if((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 3)) { // example  connect 130.208.243.61 4000 
        std::string ip_address = tokens[1];
        int port = std::stoi(tokens[2]);
        connectToServer(ip_address, port, groupID, Server);
    }
    else if(tokens[0].compare("LEAVE") == 0) {
        // Close the socket, and leave the socket handling
        // code to deal with tidying up clients etc. when
        // select() detects the OS has torn down the connection.
 
        closeClient(clientSocket, openSockets, maxfds);
    }
    else if(tokens[0].compare("WHO") == 0) {
        std::cout << "Who is logged on" << std::endl;
        std::string msg;

        for(auto const& names : clients) {
            msg += names.second->name + ",";

        }
    // Reducing the msg length by 1 loses the excess "," - which
    // granted is totally cheating.
    

    }
    // This is slightly fragile, since it's relying on the order
    // of evaluation of the if statement.
    else if((tokens[0].compare("MSG") == 0) && (tokens[1].compare("ALL") == 0)) { // senda á hvert og eitt socket þetta message
        std::string msg;
        for(auto i = tokens.begin()+2;i != tokens.end();i++) {
            msg += *i + " ";
        }

        for(auto const& pair : clients) {
            send(pair.second->sock, msg.c_str(), msg.length(),0);
        }
    }
    else if(tokens[0].compare("MSG") == 0) {
        for(auto const& pair : clients) {
            if(pair.second->name.compare(tokens[1]) == 0) {
                std::string msg;
                for(auto i = tokens.begin()+2;i != tokens.end();i++) {
                    msg += *i + " ";
                }
                send(pair.second->sock, msg.c_str(), msg.length(),0);
            }
        }
    }
    else {
        std::cout << "Unknown command from client:" << buffer << std::endl;
    }
     
}

int main(int argc, char* argv[]) {
    // Messages format
    int this_port = atoi(argv[1]);
    std::string groupID = "P3_GROUP_20";
    const char STX = 0x02;  // Start of Text
    const char ETX = 0x03;  // End of Text

    myServer myServer("130.208.243.61", this_port); // endanum verður ip address input arg

    bool finished;
    int listenSock;                 // Socket for connections to server
    int clientSock;                 // Socket of connecting client
    fd_set openSockets;             // Current open sockets 
    fd_set readSockets;             // Socket list for select()        
    fd_set exceptSockets;           // Exception socket list
    int maxfds;                     // Passed to select() as max fd in set
    struct sockaddr_in client;
    socklen_t clientLen;
    char buffer[1025];              // buffer for reading from clients

    if(argc != 2) {
        printf("Usage: chat_server <ip port>\n");
        exit(0);
    }

    // Setup socket for server to listen to

    listenSock = open_socket(this_port); 
    printf("Listening on port: %d\n", this_port);

    if(listen(listenSock, BACKLOG) < 0) {
        printf("Listen failed on port %s\n", argv[1]);
        exit(0);
    }
    else {
    // Add listen socket to socket set we are monitoring
        FD_ZERO(&openSockets);
        FD_SET(listenSock, &openSockets);
        maxfds = listenSock;  
    }

    finished = false;

    while(!finished) {
        // Get modifiable copy of readSockets
        readSockets = exceptSockets = openSockets;
        memset(buffer, 0, sizeof(buffer));

        // Look at sockets and see which ones have something to be read()
        int n = select(maxfds + 1, &readSockets, NULL, &exceptSockets, NULL);

        if(n < 0) {
            perror("select failed - closing down\n");
            finished = true;
        }
        else {
            // First, accept  any new connections to the server on the listening socket
            if(FD_ISSET(listenSock, &readSockets)) {
               clientSock = accept(listenSock, (struct sockaddr *)&client,
                                   &clientLen);
               printf("accept***\n");
               // Add new client to the list of open sockets
               FD_SET(clientSock, &openSockets);

               // And update the maximum file descriptor
               maxfds = std::max(maxfds, clientSock) ;

               // create a new client to store information.
               clients[clientSock] = new Client(clientSock);

               // Decrement the number of sockets waiting to be dealt with
               n--;

               printf("Client connected on server: %d\n", clientSock);
            }
            // Now check for commands from clients
            std::list<Client *> disconnectedClients;  
            while(n-- > 0) {
               for(auto const& pair : clients) {
                  Client *client = pair.second;

                  if(FD_ISSET(client->sock, &readSockets)) {
                      // recv() == 0 means client has closed connection
                      if(recv(client->sock, buffer, sizeof(buffer), MSG_DONTWAIT) == 0) {
                          disconnectedClients.push_back(client);
                          closeClient(client->sock, &openSockets, &maxfds);

                      }
                      // We don't check for -1 (nothing received) because select()
                      // only triggers if there is something on the socket for us.
                      else {
                          std::cout << buffer << std::endl;
                          clientCommand(client->sock, &openSockets, &maxfds, buffer, groupID, myServer); // Command 
                      }
                  }
               }
               // Remove client from the clients list
               for(auto const& c : disconnectedClients)
                  clients.erase(c->sock);
            }
        }
    }
}
