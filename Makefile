# Compiler and options
CC = g++ -std=c++11
CFLAGS = -Wall

# Source and object files for server and client
SERVER_TARGET = tsampgroup20
SERVER_SOURCE = server.cpp

SERVER_SOURCE2 = tsampgroup79
SERVER_TARGET2 = server2.cpp

CLIENT_TARGET = chat_client
CLIENT_SOURCE = client.cpp

all: $(SERVER_TARGET) $(CLIENT_TARGET)

$(SERVER_TARGET): $(SERVER_SOURCE)
	$(CC) $(CFLAGS) $(SERVER_SOURCE) -o $(SERVER_TARGET)

$(CLIENT_TARGET): $(CLIENT_SOURCE)
	$(CC) $(CFLAGS) $(CLIENT_SOURCE) -o $(CLIENT_TARGET) -lpthread

$(SERVER_TARGET2): $(SERVER_SOURCE2)
	$(CC) $(CFLAGS) $(SERVER_SOURCE2) -o $(SERVER_TARGET2)

clean:
	rm -f $(SERVER_TARGET) $(CLIENT_TARGET)
