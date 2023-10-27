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
#include <string>
#include <cstring>
#include <mutex>
#include <chrono>
#include <iostream>
#include <sstream>
#include <thread>
#include <map>

#include <unistd.h>

// fix SOCK_NONBLOCK for OSX
#ifndef SOCK_NONBLOCK
#include <fcntl.h>
#define SOCK_NONBLOCK O_NONBLOCK
#endif

#define BACKLOG  5          // Allowed length of queue of waiting connections

std::mutex mtx;  // Mutex for synchronizing access to connectionsList
// Class to keep information about this server
struct myServer {
    std::string ip_address;
    int port;
    int sock;
    std::string groupID;

    // Constructor
    myServer(const std::string& ip, int p, const std::string& ID) : ip_address(ip), port(p),groupID(ID) {}
};

// Simple class for handling connections from connections.
//
// Connection(int socket) - socket to send/receive traffic from client.
class Connection {
    public:
    int sock;              // socket of client connection
    std::string groupID;           // Limit length of name of client's user
    bool isServer = true;
    std::string ip_address;
    int port;

    Connection(int socket) : sock(socket){} 

    ~Connection(){}            // Virtual destructor defined for base class
    friend std::ostream& operator<<(std::ostream& os, const Connection& connection); // to use '<<' to send a Server object to an 'std::ostream', like std::out
};

class Message {
    public:
    std::string to_groupID;
    std::string from_groupID;
    std::string message_content;
    
    // Constructor
    Message(const std::string& toID, const std::string& fromID, const std::string& msg) : to_groupID(toID), from_groupID(fromID),message_content(msg) {}
};



// Simple class for handling queued servers that we have no et connected to
class CuteServer {
    public:
    int sock;              // socket of client connection
    std::string groupID;           // Limit length of name of client's user
    std::string ip_address;
    int port;

    CuteServer(int socket) : sock(socket){} 

    ~CuteServer(){}            // Virtual destructor defined for base class
    friend std::ostream& operator<<(std::ostream& os, const CuteServer& queued_server); // to use '<<' to send a Server object to an 'std::ostream', like std::out
};


std::vector<std::string> parseTokenToConnection(const std::string& token) {
    std::stringstream ss(token);
    std::vector<std::string> result(3); // This vector will hold groupID, ip_address, and port as strings

    std::getline(ss, result[0], ',');  // groupID
    std::getline(ss, result[1], ',');  // ip_address
    ss >> result[2];                   // port

    return result;
}

// Note: map is not necessarily the most efficient method to use here,
// especially for a server with large numbers of simulataneous connections,
// where performance is also expected to be an issue.
//
// Quite often a simple array can be used as a lookup table, 
// (indexed on socket no.) sacrificing memory for speed.

std::map<int, Connection*> connectionsList; // Lookup table for per Client information
//std::map<int, CuteServer*> queued_servers; // Lookup table for per server in queue

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
    if((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("Failed to open socket");
        return(-1);
    }
#else
    if((sock = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
    {
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
    if(setsockopt(sock, SOL_SOCKET, SOCK_NONBLOCK, &set, sizeof(set)) < 0)
    {
        perror("Failed to set SOCK_NOBBLOCK");
    }
#endif
    memset(&sk_addr, 0, sizeof(sk_addr));
    sk_addr.sin_family      = AF_INET;
    sk_addr.sin_addr.s_addr = INADDR_ANY;
    //sk_addr.sin_addr.s_addr = inet_addr("130.208.243.61"); // laga seinna
    //sk_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // laga seinna
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
void closeConnection(int clientSocket, fd_set *openSockets, int *maxfds) {
     // If this client's socket is maxfds then the next lowest
     // one has to be determined. Socket fd's can be reused by the Kernel,
     // so there aren't any nice ways to do this.
    close(clientSocket);      
    if(*maxfds == clientSocket) {
        for(auto const& p : connectionsList) {
            *maxfds = std::max(*maxfds, p.second->sock);
        }
    }
    // And remove from the list of open sockets.
    FD_CLR(clientSocket, openSockets);
}

std::vector<std::string> extractMultiCommands(const char* buffer) {
    std::vector<std::string> commands;
    const char STX = 0x02;  // Start of command
    const char ETX = 0x03;  // End of command
    const char* STX_ptr = strchr(buffer, STX);
    const char* ETX_ptr = strchr(buffer, ETX);

    while (STX_ptr && ETX_ptr && STX_ptr < ETX_ptr) {
        int extractedLength = ETX_ptr - STX_ptr - 1; // Determine the length of the extracted string
        commands.push_back(std::string(STX_ptr + 1, extractedLength)); // Push the message between STX and ETX to the vector
        
        // Move pointers to search for the next STX-ETX pair
        STX_ptr = strchr(ETX_ptr + 1, STX);
        ETX_ptr = strchr(STX_ptr, ETX);
    }

    return commands;
}



std::string extractCommand(const char* buffer) {
    const char STX = 0x02;  // Start of command
    const char ETX = 0x03;  // End of command
    const char* STX_ptr = strchr(buffer, STX);
    const char* ETX_ptr = strchr(buffer, ETX);
    // Check if both STX and ETX are present, and STX appears before ETX
    if(STX_ptr && ETX_ptr && STX_ptr < ETX_ptr) {
        int extractedLength = ETX_ptr - STX_ptr - 1;   // Determine the length of the extracted string
        return std::string(STX_ptr + 1, extractedLength); // Create and return a std::string from the portion between STX and ETX
    }

    // Return empty string if the conditions are not met
    return "";
}

// Wraps the command
std::string wrapWithSTXETX(const std::string& payload) {
    char STX = 0x02;  // Start of Text (ASCII representation)
    char ETX = 0x03;  // End of Text (ASCII representation)
    std::string ret = std::string(1, STX) + payload + std::string(1, ETX);
    return ret;
}

// Get the response for QUERYSERVERS
std::string queryserversResponse(const std::string& fromgroupID, myServer myServer) { 
    std::string response =  "SERVERS," + fromgroupID + "," + myServer.ip_address + "," + std::to_string(myServer.port) + ";"; // Should get the info for this server P3_GROUP_20,130.208.243.61,Port
    for(const auto& pair : connectionsList) {
        Connection* connection = pair.second;
        if (connection->isServer) {
            response += connection->groupID + "," + connection->ip_address + "," + std::to_string(connection->port) + ";";
        }
    }
    return response;
}

// This sends Keepalive to all connected servers every 60 seconds
void keepAliveFunction() {
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(60)); // Sleep for 60 seconds
        // Lock the mutex to safely iterate over connectionsList
        mtx.lock();
        for(auto const& pair : connectionsList) {
            Connection *connection = pair.second;
            // Send the keepalive message to each connection. 
            // Replace the message below with whatever your protocol needs.
            if(connection->isServer){
                std::string keepaliveMessage = "KEEPALIVE,0";
                std::cout << "Sending keepalive to " << connection->groupID << std::endl;
                keepaliveMessage = wrapWithSTXETX(keepaliveMessage);
                send(connection->sock, keepaliveMessage.c_str(), keepaliveMessage.size(), 0);
            } 
        }
        mtx.unlock();
    }
}

void send_queryservers(int server_sock, myServer myServer) {
    std::string queryservers = "QUERYSERVERS," + myServer.groupID + ","+ myServer.ip_address + "," + std::to_string(myServer.port); // Send QUERYSERVERS to the server
    queryservers = wrapWithSTXETX(queryservers);
    if(send(server_sock, queryservers.c_str(), queryservers.length(), 0) < 0) {
        perror("Error sending SERVERS message");
    }
    std::cout << "Sending Queryservers messege: " << queryservers <<"\n"<< std::endl; //DEBUG
}

// Creates a new connection from the socket and adds it to the connectionsList
void create_connection(int serverSock, std::string receivedGroupID, std::string ip_address, int port, bool isServer) {
    // Check if the socket already has an associated connection.
    if (connectionsList.find(serverSock) != connectionsList.end()) {
        // Close the existing connection and free memory (if needed).
        delete connectionsList[serverSock];  // free memory
    }

    Connection* newConnection = new Connection(serverSock);
    newConnection->ip_address = ip_address;
    newConnection->isServer = isServer;
    newConnection->port = port;
    newConnection->groupID = receivedGroupID;  // Set the group ID in the Connection instance
    connectionsList[serverSock] = newConnection;
}



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
    //Hér sendum við queryservers
    send_queryservers(serverSock, myServer);
    create_connection(serverSock, groupID, ip_address, port, false);
    return serverSock;
}


// Process command from client on the server
void clientCommand(int server_socket, fd_set *openSockets, int *maxfds, 
                  std::string buffer, std::string from_groupID, myServer server) 
{
    std::vector<std::string> tokens;
    std::stringstream stream(buffer);
    std::string token;

    // Split command from client into tokens for parsing
    while(std::getline(stream, token, ',')) {
        tokens.push_back(token);
    }

    // If we get QUERYSERVERS respond with SERVERS, and your server followed by all connected servers
    //also if the ip anf port is sent too
    if((tokens[0].compare("QUERYSERVERS") == 0 && tokens.size() == 2) || (tokens[0].compare("QUERYSERVERS") == 0 && tokens.size() == 4)) { 
        // Put together the SERVERS response 
        std::string servers_response = queryserversResponse(from_groupID, server);
        // Wrap it in STX and ETX
        servers_response = wrapWithSTXETX(servers_response);
        if(send(server_socket, servers_response.c_str(), servers_response.length(), 0) < 0) {
            perror("Error sending SERVERS message");
            return;
        }
        std::cout << "SERVERS sent: " << servers_response << std::endl;
        /// tEST

        
    } else if((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 3)) { // example  connect 130.208.243.61 4000 
        std::cout << "client command: " << tokens[0] << " " << tokens[1] << " " << tokens[2] << " " << std::endl; // DEBUG
        std::string ip_address = tokens[1];
        int port = std::stoi(tokens[2]);
        int socket =  connectToServer(ip_address, port, from_groupID, server);
        
        FD_SET(socket, openSockets);
        // And update the maximum file descriptor
        *maxfds = std::max(*maxfds, socket);
        //send_queryservers(server_socket, from_groupID, server); // Send QUERYSERVERS to the server eftir að búa til tengingu 


    } else if((tokens[0].compare("SERVERS") == 0)) { // example  connect 130.208.243.61 4000 
        // Save the servers in the response, the first one is the one that sent this command
        std::cout << "Fengum SERVERS og förum inn i að splitta"<< std::endl; // DEBUG
        create_connection(server_socket, tokens[1], "None", -1, true); // Create a connection from the socket
        std::vector<std::string> servers_tokens;
        std::string servers_token;
        std::stringstream servers_stream(buffer.substr(8));
        // here we could mabey need to use BFS to connect to everyone

        // After Servers take the first one and fill out the connection form
        std::vector<std::string>::size_type count = 0;
        while(std::getline(servers_stream, servers_token, ';')) {
            servers_tokens.push_back(servers_token); //Then push rest into the stream
            if (count == 0) {
                std::vector<std::string> parsedInfo= parseTokenToConnection(servers_tokens[0]);
                std::cout << "Fyrsta tokenið er: " << servers_tokens[0] << std::endl; // DEBUG
            }
            count++; 
        }
         // Create a connection from the socket
        for(std::vector<std::string>::size_type i = 1; i < servers_tokens.size(); i++) {
            std::cout << servers_tokens[i] << std::endl; //DEBUG  +
        }
        std::cout << "Þetta er eftir að við prentum út servers listann"<< std::endl; // DEBUG
    


    }else if (tokens[0].compare("LISTSERVERS") == 0) {
        std::cout << "List servers" << std::endl;
        std::string msg;
        for(auto const& pair : connectionsList) {
            Connection *connection = pair.second;
            msg += connection->groupID + "," + connection->ip_address + "," + std::to_string(connection->port) + ";";
        }
        send(server_socket, msg.c_str(), msg.length(),0);
        std::cout << "Message sent was: " << msg << std::endl;

    }/*else if(tokens[0].compare("SENDMSG") == 0) {
        std::cout << "Send message" << std::endl;
        std::string msg;
        for(auto const& pair : connectionsList) {
            Connection *connection = pair.second;
            msg += connection->groupID + "," + connection->ip_address + "," + std::to_string(connection->port) + ";";
        }
        send(server_socket, msg.c_str(), msg.length(),0);
        std::cout << "Message sent was" << msg << std::endl;
    }else if(tokens[0].compare("FETCHMSG") == 0) {
    
    }*/
    
    else {
        std::cout << "Unknown command:" << buffer << std::endl;
    }   
}

int main(int argc, char* argv[]) {
    // Messages format
    int this_port = atoi(argv[1]);
    std::string groupID = "P3_GROUP_20";
    char STX = 0x02;  // Start of command
    char ETX = 0x03;  // End of command

    myServer myServer("130.208.243.61", this_port, groupID);
    //myServer myServer("127.0.0.1", this_port);

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
    } else {
        // Add listen socket to socket set we are monitoring
        FD_ZERO(&openSockets);
        FD_SET(listenSock, &openSockets);
        maxfds = listenSock;
    }

    finished = false;
    std::thread keepAliveThread(keepAliveFunction); // Start the keepalive thread
    while(!finished) {
        // Get modifiable copy of readSockets
        readSockets = exceptSockets = openSockets;
        memset(buffer, 0, sizeof(buffer));

        // Look at sockets and see which ones have something to be read()
        int n = select(maxfds + 1, &readSockets, NULL, &exceptSockets, NULL);
        if(n < 0) {
            perror("select failed - closing down\n");
            finished = true;
        } else {
            // First, accept  any new connections to the server on the listening socket
            if(FD_ISSET(listenSock, &readSockets)) {
                clientSock = accept(listenSock, (struct sockaddr *)&client, &clientLen);
                printf("accept***\n");
                // Add new client to the list of open sockets
                FD_SET(clientSock, &openSockets);
                // And update the maximum file descriptor
                maxfds = std::max(maxfds, clientSock) ;
                send_queryservers(clientSock, myServer); // senda bara strax
                
                char handshakeBuffer[1025];
                memset(handshakeBuffer, 0, sizeof(handshakeBuffer));
                int handshakeBytes = recv(clientSock, handshakeBuffer, sizeof(handshakeBuffer) - 1, 0);  // This time, we block until we get a response
                std::cout << "Print HandshakeBuffer: " << handshakeBuffer << std::endl; //DEBUG
                if(handshakeBytes > 0 && strcmp(handshakeBuffer, "SECRET_KATRIN") == 0) {
                    std::cout << "Secret client Handshake Received" << std::endl; //DEBUG
                    create_connection(clientSock, groupID, myServer.ip_address, myServer.port, false); // Create a connection from the socket
                    printf("Our Client is connected on server with id: %s\n", groupID.c_str());
                } else {
                    std::string extracted = extractCommand(handshakeBuffer);
                    if(extracted.substr(0, 13) == "QUERYSERVERS,") {
                        std::vector<std::string> tokens;
                        std::stringstream stream(extracted);
                        std::string token;
                        // Split command from client into tokens for parsing
                        while(std::getline(stream, token, ',')) {
                                tokens.push_back(token);
                            }
                        std::cout << "Server tries to connect with Queryservers" << std::endl; //DEBUG
                        create_connection(clientSock, tokens[1], "None", -1, true); // Create a connection from the socket
                        clientCommand(clientSock, &openSockets, &maxfds, extracted, groupID, myServer);
                    }
                }
                printf("Client connected on server: %d\n", clientSock);
                n--;
            }
            // Now check for commands from clients
            std::list<Connection *> disconnectedServers;  
            while(n-- > 0) {
                memset(buffer, 0, sizeof(buffer));
                for(auto const& pair : connectionsList) {
                    Connection *connection = pair.second;
                    // Check which client has sent us something
                    //std::cout << "Misstum af seinni pakkanum" << std::endl;
                    if(FD_ISSET(connection->sock, &readSockets)) {
                        int commandBytes = recv(connection->sock, buffer, sizeof(buffer), MSG_DONTWAIT); // this is the command bytes from client
                        std::cout << "Print buffer: " << buffer << std::endl; //DEBUG
                        if(commandBytes == 0) {
                            disconnectedServers.push_back(connection);
                            closeConnection(connection->sock, &openSockets, &maxfds);
                            std::cout << "Client closed connection: " << connection->sock << std::endl;
                        } else {
                            std::cout << "Command bytes: " << commandBytes << std::endl;   //DEBUG
                            // We don't check for -1 (nothing received) because select()
                            // only triggers if there is something on the socket for us.
                            char* STX_ptr = strchr(buffer, STX);// Find pointers to STX and ETX within the buffer using strchr
                            char* ETX_ptr = strchr(buffer, ETX);
                            
                            if (STX_ptr && ETX_ptr && STX_ptr < ETX_ptr) {
                                // STX and ETX found, extract the string between STX and ETX
                                std::string extracted = extractCommand(buffer);
                                std::cout << "Fer inn sem server command: \n" << std::endl;
                                clientCommand(connection->sock, &openSockets, &maxfds, extracted, groupID, myServer);
                            } else {
                                // STX not found or ETX not found or neither then treat it as a client command
                                std::cout << "Fer inn sem client command:\n" << std::endl;
                                clientCommand(connection->sock, &openSockets, &maxfds, buffer, groupID, myServer);
                            }
                        }
                    }
                }
                // Remove client from the clients list
                for(auto const& c : disconnectedServers)
                    connectionsList.erase(c->sock);
            }
        }
    } 
    keepAliveThread.join();
}
    
