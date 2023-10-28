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
const int MAX_SERVER_CONNECTIONS = 15;

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
    bool isServer = false;
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


std::vector<std::string> splitTokens(const std::string& token) {
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
std::map<int, CuteServer*> queuedServers; // Lookup table for per server in queue
std::map<std::string, std::vector<Message>> messageStore; // Lookup table for messages stored as vectors with key being group ID
std::map<std::string, size_t> currentMessageIndex; // MEssage pointer to the current message in the messageStore
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
        if (connection->isServer && (connection->groupID != "Unknown") && (connection->ip_address != "None")) { // If the instance is a server and if the id is not None
            response += connection->groupID + "," + connection->ip_address + "," + std::to_string(connection->port) + ";";
        }
    }
    return response;
}

// This sends Keepalive to all connected servers every 60 seconds
void keepAliveFunction(fd_set *openSockets, int *maxfds) {
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
                ssize_t bytes_sent = send(connection->sock, keepaliveMessage.c_str(), keepaliveMessage.size(), 0);

                // Catch if the error the socket was closed
                if (bytes_sent == -1) {
                    perror("send");
                    // Close the socket and cleanup
                    closeConnection(connection->sock, openSockets, maxfds);
                }
            } 
        }
        mtx.unlock();
    }
}

Connection* isConnected(const std::string& groupId) {
    for (const auto& pair : connectionsList) {
        Connection* connection = pair.second;
        if ((connection->groupID == groupId) && (connection->isServer)) {
            return connection;  // return the Connection object if found
        }
    }
    return nullptr;  // return nullptr if not connected
}
// Þetta er fyrir send messages til að finna connection
Connection* findObject(const std::string& groupId) {
    for (const auto& pair : connectionsList) {
        Connection* connection = pair.second;
        if (connection->groupID == groupId) {
            return connection;  // return the Connection object if found
        }
    }
    return nullptr;  // return nullptr if not connected
}


// Function that stores messages in the messageStore
void storeMessage(const std::string& toGroupID, const std::string& fromGroupID, const std::string& msg) {
    Message newMessage(toGroupID, fromGroupID, msg);
    messageStore[toGroupID].push_back(newMessage);
    std::cout << "Message stored in messageStore" << std::endl;
}

// Function that gets the next message for a group if there is any
std::string getNextMessageForGroup(const std::string& groupID) {
    // Check if there are messages for the group
    if (messageStore.count(groupID) > 0) {
        // If the group doesn't have a current index, initialize it to 0
        if (currentMessageIndex.count(groupID) == 0) {
            currentMessageIndex[groupID] = 0;
        }
        size_t index = currentMessageIndex[groupID]; // Get the current index for the group
        // Ensure we're not out of bounds
        if (index < messageStore[groupID].size()) {
            std::string msg = messageStore[groupID][index].from_groupID + "," + messageStore[groupID][index].message_content;
            // Increment the index for next time
            currentMessageIndex[groupID]++;
            return msg;
        } else {
            // No more messages to send; you can handle this however you want
            return "No more messages for group: " + groupID;
        }
    }
    return "No messages for group: " + groupID;
}

void sendQueryservers(int server_sock, myServer myServer) {
    std::string queryservers = "QUERYSERVERS," + myServer.groupID + ","+ myServer.ip_address + "," + std::to_string(myServer.port); // Send QUERYSERVERS to the server
    queryservers = wrapWithSTXETX(queryservers);
    if(send(server_sock, queryservers.c_str(), queryservers.length(), 0) < 0) {
        perror("Error sending SERVERS message");
    }
    std::cout << "Sending Queryservers message: " << queryservers <<"\n"<< std::endl; //DEBUG
}

// Creates a new connection from the socket and adds it to the connectionsList
void createConnection(int serverSock, std::string receivedGroupID, std::string ip_address, int port, bool isServer) {
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
    // Here count the servers that are connected
    int serverCount = 0;
    // Add to the server count if the connection is server
    for (const auto& pair : connectionsList) {
        if (pair.second->isServer) {
            serverCount++;
        }
    }
    // Compare to maximum server connections
    if(serverCount >= MAX_SERVER_CONNECTIONS) {
        std::cerr << "Max server connections reached. Not connecting to " << ip_address << ":" << port << std::endl;
        return -1;
    }
    // If servers are fewer than 15 then connect
    
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
    sendQueryservers(serverSock, myServer);
    createConnection(serverSock, groupID, ip_address, port, true);
    // Þurfum að adda hér í messengestore pæla seinna
    
    return serverSock;
}

// Takes in a vector of servers with comma seperated tokens, group_id,
void connectToServersVector(std::vector<std::string> servers, myServer server) {
    for(std::vector<std::string>::size_type i = 1; i < servers.size(); i++) {
        std::vector<std::string> connection_tokens = splitTokens(servers[i]);
        if (connection_tokens[0] != server.groupID)  {
            if(!isConnected(connection_tokens[0])) {
                std::cout << "\nConnecting to server: " << connection_tokens[0] << " " << connection_tokens[1] << " " << connection_tokens[2] << std::endl; //DEBUG
                connectToServer(connection_tokens[1], std::stoi(connection_tokens[2]), connection_tokens[0], server);
            } else {
                std::cout << "\nServer: " << connection_tokens[0] << " is already connected. Skipping connection." << std::endl; //DEBUG
            }
        }
    }
}





// Process command from client on the server
void serverCommand(int server_socket, fd_set *openSockets, int *maxfds, 
                  std::string buffer, myServer server) 
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

            std::string servers_response = queryserversResponse(server.groupID, server);
            // Wrap it in STX and ETX
            servers_response = wrapWithSTXETX(servers_response);
            if(send(server_socket, servers_response.c_str(), servers_response.length(), 0) < 0) {
                perror("Error sending SERVERS message");
                return;
            }
            std::cout << "SERVERS sent: " << servers_response << std::endl;
            createConnection(server_socket,tokens[1],"",-1,true);
            /// tEST
    } else if((tokens[0].compare("SERVERS") == 0)) { // example  connect 130.208.243.61 4000 
        // Save the servers in the response, the first one is the one that sent this command
        std::vector<std::string> servers_tokens;
        std::string servers_token;
        std::stringstream servers_stream(buffer.substr(8));

        // After Servers take the first one and fill out the connection form
        while(std::getline(servers_stream, servers_token, ';')) {
            servers_tokens.push_back(servers_token); //Then push rest into the stream
        }
        
        // Now we need to update the information for the server that sends us SERVERS, he is token[0]
        std::vector<std::string> first_server = splitTokens(servers_tokens[0]);
        
        createConnection(server_socket,first_server[0],first_server[1], std::stoi(first_server[2]), true); // bætti þessu við sjáu,m hvort non breytist

        // Print out the server that are to send QUERYSERVERS
        std::cout << "\nServers to connect to: "<< std::endl; // DEBUG
        for(std::vector<std::string>::size_type i = 1; i < servers_tokens.size(); i++) {
            std::cout << servers_tokens[i] << std::endl; //DEBUG  +
        }
        // Skoða guard um tvítenginu
        connectToServersVector(servers_tokens, server);

    } else if(tokens[0].compare("SEND_MSG") == 0 && (tokens.size() == 4)) { // SEND MSG,<TO GROUP ID>,<FROM GROUP ID>,<Message content>
    // This is if we receive a message from another server
        std::string to_group = tokens[1]; // þetta er þá td P3_GROUP_20 
        std::string from_group = tokens[2]; // þetta er þá td P3_GROUP_30
        std::string message_contents = tokens[3]; // þetta er þá td "Hello World"
        std::cout << "Message received from " << from_group << ": " << message_contents << std::endl; // DEBUG
        Connection* connection = findObject(from_group); // check if connected
        std::cout << "Message from: "<< tokens[2] << "sent to: " << connection->groupID << std::endl; // DEBUG
        if(connection) { //if connected or in connectionlist
            std::string msg =  message_contents; // Create the message to send
            ssize_t bytes_sent = send(connection->sock, msg.c_str(), msg.length(),0); // Send the message to the server
            // Check if the server has closed connection nad detect broken pipe
            if (bytes_sent == -1) {
                if (errno == EPIPE) {
                    std::cerr << "Detected broken pipe!" << std::endl;
                    // Handle the error, e.g., close the socket, remove it from your data structures, etc.
                    closeConnection(connection->sock, openSockets, maxfds);
                } else {
                    perror("send");
                }
            }
        } else {
            std::cout << "There has been an error sending message to client" << from_group << std::endl;
        }
    } else if(tokens[0].compare("FETCH_MSGS") == 0 && (tokens.size() == 2)) { 
        // Hér þurfum við að senda á hóp sem er með group id og socket til að fá messageinn 
    } else if(tokens[0].compare("STATUSREQ") == 0 && (tokens.size() == 2)) { 
    
    } else if(tokens[0].compare("STATUSRESP") == 0 && (tokens.size() > 4)) { 
    
    } else if(tokens[0].compare("KEEPALIVE") == 0 && (tokens.size() == 2)){
        // If we get a keepalive from a server we print out the server id
        std::cout << "Keepalive received from " << connectionsList[server_socket]->groupID << std::endl;
        if(tokens[1] != "0") {
            // If keepalive is not 0 we send a fetch message to the server to receive messages
            // Kannski ekki sniðugt
            //serverCommand(server_socket, openSockets, maxfds, "FETCH_MSGS," + connectionsList[server_socket]->groupID, server); // smá recursion stemming
        } else {
            std::cout << "No Messages from group: "<< connectionsList[server_socket]->groupID << std::endl;
        }
    } else {
        // prints out the unknown command from the server 
        std::cout << "Unknown command from server " << connectionsList[server_socket]->groupID << ": "  << buffer << std::endl;
    }   
}

void fetchMessage_helper(int server_socket, int *maxfds, std::string buffer, myServer server) {
    // Beffer sem kemur inn er segjum Fetch_MSGS,P3_GROUP_20
    send(server_socket, buffer.c_str(), buffer.length(), 0);
    std::cout << "Message sent was: " << buffer << std::endl;
    char messageBuffer[1025];
    memset(messageBuffer, 0, sizeof(messageBuffer));
    int messageBytes = recv(server_socket, messageBuffer, sizeof(messageBuffer) - 1, 0);  // This time, we block until we get a response

}

// Gets all the messages 
std::vector<Message> getMessagesForGroup(const std::string& groupID, const std::map<std::string, std::vector<Message>>& messageStore) {
    // Check if the groupID exists in the map
    if (messageStore.find(groupID) != messageStore.end()) {
        return messageStore.at(groupID);
    }

    // Return an empty vector if no messages found for the given groupID
    return std::vector<Message>();
}

// Commands that are from the client
void clientCommand(int server_socket, fd_set *openSockets, int *maxfds, 
                  std::string buffer, myServer server) 
{
    buffer.erase(std::remove(buffer.begin(), buffer.end(), '\n'), buffer.end()); // Remove the newline character from the end of the string
    std::vector<std::string> tokens;
    std::stringstream stream(buffer);
    std::string token;

    // Split command from client into tokens for parsing
    while(std::getline(stream, token, ',')) {
        tokens.push_back(token);
    }
    // If we get CONNECT, connect to the server and send QUERYSERVERS
    if((tokens[0].compare("CONNECT") == 0) && (tokens.size() == 3)) { // example  connect 130.208.243.61 4000 
        std::cout << "client command: " << tokens[0] << " " << tokens[1] << " " << tokens[2] << " " << std::endl; // DEBUG
        std::string ip_address = tokens[1];
        int port = std::stoi(tokens[2]);
        int socket =  connectToServer(ip_address, port, "Unknown", server);
        
        FD_SET(socket, openSockets);
        // And update the maximum file descriptor
        *maxfds = std::max(*maxfds, socket);
        //sendQueryservers(server_socket, from_groupID, server); // Send QUERYSERVERS to the server eftir að búa til tengingu 

    } else if(tokens[0].compare("LISTSERVERS") == 0) {
        std::string msg;
        for(auto const& pair : connectionsList) {
            Connection *connection = pair.second;
            if(connection->isServer) { // Make sure to check if the connection is a server
                msg += connection->groupID + "," + connection->ip_address + "," + std::to_string(connection->port) + ";";
            }
        }
        if(msg.empty()) { // checks if the msg is empty to print out no servers connected
            std::cout << "No servers found." << std::endl;
            msg = "no server connected";
        }
        ssize_t bytes_sent = send(server_socket, msg.c_str(), msg.length(),0); // Send the message to the server
        // Check if the server has closed connection nad detect broken pipe
        if (bytes_sent == -1) {
            if (errno == EPIPE) {
                std::cerr << "Detected broken pipe!" << std::endl;
                // Handle the error, e.g., close the socket, remove it from your data structures, etc.
                closeConnection(server_socket, openSockets, maxfds);
            } else {
                perror("send");
            }
        }
        std::cout << "Message sent was: " << msg << std::endl;

    } else if(tokens[0].compare("SENDMSG") == 0 && (tokens.size() == 3)) {
        // If we were to send message to a server that is is the process of sending
        std::cout << "Send message" << std::endl; // bREYTA prentinu
        Connection* connection = isConnected(tokens[1]); // check if connected
        std::cout << "Message from: "<< server.groupID << "sent to: " << connection->groupID << std::endl; // DEBUG
        if(connection) { //if connected or in connectionlist
            std::cout << "Server " << tokens[1] << " is connected: " << std::endl; // Print out client connected on server
            std::string msg = "SEND_MSG," + connection->groupID + "," + server.groupID + "," + tokens[2]; // Create the message to send
            std::cout << "Message sent was: " << msg << std::endl;
            msg = wrapWithSTXETX(buffer); // Wrap the message with STX and ETX
            ssize_t bytes_sent = send(connection->sock, msg.c_str(), msg.length(),0); // Send the message to the server
            // Check if the server has closed connection nad detect broken pipe
            if (bytes_sent == -1) {
                if (errno == EPIPE) {
                    std::cerr << "Detected broken pipe!" << std::endl;
                    // Handle the error, e.g., close the socket, remove it from your data structures, etc.
                    closeConnection(connection->sock, openSockets, maxfds);
                } else {
                    perror("send");
                }
            }
        } else {
            // Here we can store the messege to the messege list have to intertwine with keepalive
            storeMessage(tokens[1], server.groupID, tokens[2]);
            std::cout << "Client is not connected to server: " << tokens[1] << std::endl;
        }
    
    } else if(tokens[0].compare("GETMSG") == 0 && (tokens.size() == 2)) {
        std::cout << "Get message" << std::endl;
        std::string msg;
        msg = getNextMessageForGroup(tokens[1]); // Get the next message for our group
        send(server_socket, msg.c_str(), msg.length(), 0); // send the message to the client
        std::cout << "Message sent was: " << msg << std::endl;
    } else {
        std::cout << "Unknown command from client:" << buffer << std::endl;
    } 
}




int main(int argc, char* argv[]) {
    // Messages format
    int this_port = atoi(argv[1]);
    std::string ourGroupID = "P3_GROUP_20";
    char STX = 0x02;  // Start of command
    char ETX = 0x03;  // End of command

    myServer myServer("130.208.243.61", this_port, ourGroupID);
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
    char buffer[1025];              // buffer for reading from clients+
    std::string leftoverBuffer;     // buffer for reading from clients

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
    std::thread keepAliveThread(keepAliveFunction, &openSockets, &maxfds);
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
                sendQueryservers(clientSock, myServer); // sending right away
                
                char handshakeBuffer[1025];
                memset(handshakeBuffer, 0, sizeof(handshakeBuffer));
                int handshakeBytes = recv(clientSock, handshakeBuffer, sizeof(handshakeBuffer) - 1, 0);  // This time, we block until we get a response
                std::cout << "Print HandshakeBuffer: " << handshakeBuffer << std::endl; //DEBUG
                if(handshakeBytes > 0 && strcmp(handshakeBuffer, "SECRET_KATRIN") == 0) {
                    std::cout << "Secret client Handshake Received" << std::endl; //DEBUG
                    createConnection(clientSock, ourGroupID, myServer.ip_address, myServer.port, false); // Create a connection from the socket
                    printf("Our Client is connected on server with id: %s\n", ourGroupID.c_str());
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
                        if (!isConnected(tokens[1])) {
                            std::cout << "Server tries to connect with Queryservers" << std::endl; //DEBUG
                            std::cout << "GROUPIDIDIDIDID: " << tokens[1] << std::endl; //DEBUG
                            createConnection(clientSock, tokens[1], "None", -1, true); // Create a connection from the socket
                            serverCommand(clientSock, &openSockets, &maxfds, extracted, myServer);
                        } else {
                            std::cout << "Server is already connected" << std::endl; //DEBUG
                        }
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
                            try{
                                // We have received commandBytes of data, but it can be many commands
                                leftoverBuffer.append(buffer, commandBytes);
                                size_t start_pos = 0;
                                // While we have something in the buffer
                                while(true) {
                                    // Search for STX and ETX in the leftoverBuffer starting from start_pos
                                    size_t stx_pos = leftoverBuffer.find(STX, start_pos);
                                    size_t etx_pos = leftoverBuffer.find(ETX, start_pos);

                                    // If both STX and ETX are found and in correct order
                                    if(stx_pos != std::string::npos && etx_pos != std::string::npos && stx_pos < etx_pos) {
                                        std::string extracted = leftoverBuffer.substr(stx_pos + 1, etx_pos - stx_pos - 1);
                                        std::cout << "\nCommand from server " << connection->groupID << ": " << extracted << std::endl;
                                        serverCommand(connection->sock, &openSockets, &maxfds, extracted, myServer);
                                        
                                        // Move to the position after the found ETX for the next iteration
                                        start_pos = etx_pos + 1;
                                    } else {
                                        break; // Exit the loop if we can't find a complete command
                                    }
                                }
                                if (start_pos < leftoverBuffer.size()) {
                                    std::cout << "Leftover buffer for client: " << leftoverBuffer << std::endl; //DEBUG
                                    clientCommand(connection->sock, &openSockets, &maxfds, leftoverBuffer.c_str(), myServer);
                                    leftoverBuffer.clear();
                                }
                                leftoverBuffer.erase(0, start_pos);
                            
                            } catch (const std::length_error &le) {  // Catching string error that makes the server cras
                                std::cerr << "Length error: " << le.what() << std::endl;
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
    
                            /*std::cout << "Command bytes: " << commandBytes << std::endl;   //DEBUG
                            // We don't check for -1 (nothing received) because select()
                            // only triggers if there is something on the socket for us.
                            char* STX_ptr = strchr(buffer, STX);// Find pointers to STX and ETX within the buffer using strchr
                            char* ETX_ptr = strchr(buffer, ETX);
                            
                            if (STX_ptr && ETX_ptr && STX_ptr < ETX_ptr) {
                                // STX and ETX found, extract the string between STX and ETX
                                std::string extracted = extractCommand(buffer);
                                serverCommand(connection->sock, &openSockets, &maxfds, extracted, myServer);
                            } else {*/

                            // STX not found or ETX not found or neither then treat it as a client command
                            