# Compiler and options
CC = g++ -std=c++11
CFLAGS = -Wall

# Source and object files for server, server2 and client
SERVER_TARGET = tsampgroup20
SERVER_SOURCE = server.cpp

SERVER2_TARGET = tsampgroup79
SERVER2_SOURCE = server2.cpp

CLIENT_TARGET = chat_client
CLIENT_SOURCE = client.cpp

all: $(SERVER_TARGET) $(SERVER2_TARGET) $(CLIENT_TARGET)

$(SERVER_TARGET): $(SERVER_SOURCE)
	$(CC) $(CFLAGS) $(SERVER_SOURCE) -o $(SERVER_TARGET)

$(SERVER2_TARGET): $(SERVER2_SOURCE)
	$(CC) $(CFLAGS) $(SERVER2_SOURCE) -o $(SERVER2_TARGET) 

$(CLIENT_TARGET): $(CLIENT_SOURCE)
	$(CC) $(CFLAGS) $(CLIENT_SOURCE) -o $(CLIENT_TARGET) -lpthread

clean:
	rm -f $(SERVER_TARGET) $(SERVER2_TARGET) $(CLIENT_TARGET)
