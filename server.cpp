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

// Class to keep information about this server
struct myServer {
    std::string ip_address;
    int port;
    int sock;

    // Constructor
    myServer(const std::string& ip, int p) : ip_address(ip), port(p) {}
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

std::ostream& operator<<(std::ostream& os, const Connection& connection)
{
    os << connection.groupID << "," << connection.ip_address << "," << connection.port; // server obj as GROUP_ID,IP,Port
    return os;
}

// Note: map is not necessarily the most efficient method to use here,
// especially for a server with large numbers of simulataneous connections,
// where performance is also expected to be an issue.
//
// Quite often a simple array can be used as a lookup table, 
// (indexed on socket no.) sacrificing memory for speed.

std::map<int, Connection*> connectionsList; // Lookup table for per Client information

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
    //sk_addr.sin_addr.s_addr = INADDR_ANY;
    //sk_addr.sin_addr.s_addr = inet_addr("130.208.243.61"); // laga seinna
    sk_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // laga seinna
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

    printf("Client closed connection: %d\n", clientSocket);

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

std::string extractCommand(const char* buffer) {
    const char STX = 0x02;  // Start of command
    const char ETX = 0x03;  // End of command
    
    const char* STX_ptr = strchr(buffer, STX);
    const char* ETX_ptr = strchr(buffer, ETX);

    // Check if both STX and ETX are present, and STX appears before ETX
    std::cout << "Förum við hingað inn" << std::endl; //DEBUG
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
    std::cout << response << std::endl; //DEBUG
    return response;
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
        std::cout << "Received response after connection: " << responseBuffer <<std::endl;
    }
    std::string receivedResponse = extractCommand(responseBuffer);   // Convert char array to string

    if(receivedResponse.substr(0, 13) == "QUERYSERVERS,") {
        // Now we should receive QUERYSERVERS response with the group id from the newly connected server
        std::string receivedGroupID = receivedResponse.substr(13);  // Extract everything after "QUERYSERVERS,"
        Connection* newConnection = new Connection(serverSock);
        newConnection->ip_address = ip_address;
        newConnection->port = port;
        newConnection->groupID = receivedGroupID;  // Set the group ID in the Connection instance
        connectionsList[serverSock] = newConnection;
    }

    std::string queryservers = "QUERYSERVERS," + groupID; // Send QUERYSERVERS to the server
    queryservers = wrapWithSTXETX(queryservers);

    
    if(send(serverSock, queryservers.c_str(), queryservers.length(), 0) < 0) {
        perror("Error sending SERVERS message");
    }
    std::cout << "SERVERS sent: " << queryservers << std::endl; //DEBUG


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
    if(tokens[0].compare("QUERYSERVERS") == 0 && tokens.size() == 2) {    
        // Put together the SERVERS response 
        std::string servers_response = queryserversResponse(from_groupID, server);
        // Wrap it in STX and ETX
        servers_response = wrapWithSTXETX(servers_response);
        if(send(server_socket, servers_response.c_str(), servers_response.length(), 0) < 0) {
            perror("Error sending SERVERS message");
            return;
        }
        std::cout << "SERVERS sent: " << servers_response << std::endl;
    }
    if((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 3)) { // example  connect 130.208.243.61 4000 
        std::cout << "client command: " << tokens[0] << " " << tokens[1] << " " << tokens[2] << " " << std::endl; // DEBUG
        std::string ip_address = tokens[1];
        int port = std::stoi(tokens[2]);
        int socket =  connectToServer(ip_address, port, from_groupID, server);
        FD_SET(socket, openSockets);
        // And update the maximum file descriptor
        *maxfds = std::max(*maxfds, socket);
    
    }
  /*if((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 2))
  {
     connectionsList[clientSocket]->groupID = tokens[1];
  }
  else if(tokens[0].compare("LEAVE") == 0)
  {
      // Close the socket, and leave the socket handling
      // code to deal with tidying up clients etc. when
      // select() detects the OS has torn down the connection.
 
      closeConnection(clientSocket, openSockets, maxfds);
  }
  else if(tokens[0].compare("WHO") == 0)
  {
     std::cout << "Who is logged on" << std::endl;
     std::string msg;

     for(auto const& groupID : connectionsList)
     {
        msg += groupID.second->groupID + ",";

     }
     // Reducing the msg length by 1 loses the excess "," - which
     // granted is totally cheating.
     send(clientSocket, msg.c_str(), msg.length()-1, 0);

  }
  // This is slightly fragile, since it's relying on the order
  // of evaluation of the if statement.
  else if((tokens[0].compare("MSG") == 0) && (tokens[1].compare("ALL") == 0))
  {
      std::string msg;
      for(auto i = tokens.begin()+2;i != tokens.end();i++) 
      {
          msg += *i + " ";
      }

      for(auto const& pair : connectionsList)
      {
          send(pair.second->sock, msg.c_str(), msg.length(),0);
      }
  }
  else if(tokens[0].compare("MSG") == 0)
  {
      for(auto const& pair : connectionsList)
      {
          if(pair.second->groupID.compare(tokens[1]) == 0)
          {
              std::string msg;
              for(auto i = tokens.begin()+2;i != tokens.end();i++) 
              {
                  msg += *i + " ";
              }
              send(pair.second->sock, msg.c_str(), msg.length(),0);
          }
      }
  }*/
    else {
        std::cout << "Unknown command from client:" << buffer << std::endl;
    }
     
}

int main(int argc, char* argv[]) {
    // Messages format
    int this_port = atoi(argv[1]);
    std::string groupID = "P3_GROUP_20";
    const char STX = 0x02;  // Start of command
    const char ETX = 0x03;  // End of command

    //myServer myServer("130.208.243.61", this_port);
    myServer myServer("127.0.0.1", this_port);

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

    while(!finished) {
        // Get modifiable copy of readSockets
        readSockets = exceptSockets = openSockets;
        memset(buffer, 0, sizeof(buffer));

        // Look at sockets and see which ones have something to be read()
        int n = select(maxfds + 1, &readSockets, NULL, &exceptSockets, NULL);
        std::cout << "ennnnnnn " << n << std::endl; //DEBUG
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

                // create a new client to store information.
                // connectionsList[clientSock] = new Connection(clientSock);

                // Temporary buffer to read the initial message
                char tempBuffer[1024] = {0};
                int bytesRead = recv(clientSock, tempBuffer, sizeof(tempBuffer) - 1, 0); // leaving space for null-terminator
                
                if(bytesRead > 0) {
                    std::string receivedResponse = tempBuffer;
                    if (receivedResponse == "SECRET_KATRIN") { // Only the server that sends this string gets to be added to the connected list
                        // create a new client to store information.
                        Connection* newConnection = new Connection(clientSock);
                        newConnection->groupID = groupID;  // Set the group ID in the Connection instance
                        connectionsList[clientSock] = newConnection;
                        

                    } else if(receivedResponse.substr(0, 13) == "QUERYSERVERS,") {
                        std::string receivedGroupID = receivedResponse.substr(13);  // Extract everything after "QUERYSERVERS,"
                        Connection* newConnection = new Connection(clientSock);
                        newConnection->groupID = receivedGroupID;  // Set the group ID in the Connection instance
                        connectionsList[clientSock] = newConnection;
                    }
                }
                // Decrement the number of sockets waiting to be dealt with
                n--;
                std::cout << n << std::endl;
                printf("Client connected on server: %d\n", clientSock);
                }
                for(auto const& pair : connectionsList) {
                        Connection *connection = pair.second;
                        std::cout << connection << std::endl;}
                // Now check for commands from clients
                std::list<Connection *> disconnectedServers;  
                while(n-- > 0) {
                    std::cout << "HíHí" << std::endl; // Debug
                    for(auto const& pair : connectionsList) {
                        Connection *connection = pair.second;
                        std::cout << "Aðalstopp" << std::endl; // Debug
                        if(FD_ISSET(connection->sock, &readSockets)) {
                            std::cout << "Fyrsta stopp" << std::endl; // Debug
                            int commandBytes = recv(connection->sock, buffer, sizeof(buffer), MSG_DONTWAIT);
                            // recv() == 0 means client has closed connection
                            if(commandBytes == 0) {
                                disconnectedServers.push_back(connection);
                                closeConnection(connection->sock, &openSockets, &maxfds);
                                std::cout << "Client closed connection: " << connection << std::endl;

                            } else {
                                // We don't check for -1 (nothing received) because select()
                                // only triggers if there is something on the socket for us.
                                char* STX_ptr = strchr(buffer, STX);// Find pointers to STX and ETX within the buffer using strchr
                                char* ETX_ptr = strchr(buffer, ETX);
                                std::cout << buffer << std::endl;
        
                                if (STX_ptr && ETX_ptr && STX_ptr < ETX_ptr) {
                                    /*// STX and ETX found, extract the string between STX and ETX
                                    std::string extracted(STX_ptr + 1, ETX_ptr - STX_ptr - 1);*/

                                    //int extractedLength = ETX_ptr - STX_ptr - 1;// Determine the length of the extracted string
                                    //char extracted[extractedLength + 1];// Create a char array of the required size plus one for the null terminator
                                    //strncpy(extracted, STX_ptr + 1, extractedLength);// Copy the portion of the original char buffer to this new array
                                    //extracted[extractedLength] = '\0';// Null-terminate the new array

                                    //std::cout << "Extracted command: " << extracted << std::endl;
                                    std::string extracted = extractCommand(buffer);
                                    std::cout << "Extracted command: " << extracted << std::endl; //DEBUG
                                    clientCommand(connection->sock, &openSockets, &maxfds, extracted, groupID, myServer);
                                } else {
                                    // STX not found or ETX not found or neither then treat it as a client command
                                    std::cout << "Annað stopp" << std::endl; //DEBUG
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
    }

