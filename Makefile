SHELL := /bin/bash
#Type 'make test' for testing
#or simply 'make' to build all targets

CC=g++
ROOT=$(CURDIR)
SRC=$(ROOT)/src


###  3rd party libraries ###
HASHLIB=$(ROOT)/3rdParty/hash-library
#header-only 3rdPartyraries:
TCLAP=$(ROOT)/3rdParty/tclap-1.2.1/include
CATCH=$(ROOT)/3rdParty/Catch/single_include
SPDLOG=$(ROOT)/3rdParty/spdlog/include


### Object dependencies ###
COMMON_OBJS=$(SRC)/packets/radius_packet.o $(SRC)/packets/eap_packet.o $(SRC)/logging.o \
			$(HASHLIB)/md5.o $(SRC)/packets/common.o $(SRC)/auth_common.o $(SRC)/crypto.o \
			$(SRC)/packets/utils.o $(SRC)/users.o $(HASHLIB)/crc32.o $(HASHLIB)/sha1.o \
			$(HASHLIB)/sha3.o $(HASHLIB)/sha256.o $(SRC)/sockets.o $(SRC)/utils_net.o

SERVER_OBJS=$(SRC)/server.o $(SRC)/connection.o $(SRC)/radius_server.o $(COMMON_OBJS)

CLIENT_OBJS=$(SRC)/client.o $(SRC)/connection.o $(COMMON_OBJS)

TESTS_OBJS=$(SRC)/all_tests.o $(SRC)/test/radius_server_test.o $(SRC)/test/logging_test.o \
		   $(SRC)/test/packet_test.o $(SRC)/test/auth_common_test.o $(SRC)/test/users_test.o \
		   $(SRC)/test/crypto_test.o  $(SRC)/radius_server.o $(COMMON_OBJS)

### Targets ###
SERVER=server
CLIENT=client
TESTS=all_tests

### Include flags ###
COMMON_INC=-I$(HASHLIB) -I$(TCLAP) -I$(SRC) -I$(SPDLOG) -I$(SRC)/linux

SERVER_INC=$(COMMON_INC) 
CLIENT_INC=$(COMMON_INC)
TESTS_INC=-I$(HASHLIB) -I$(CATCH) -I$(SRC) -I$(SPDLOG) 

### Other flags ###
CFLAGS= -Wall -std=c++11


all: $(SERVER) $(CLIENT) $(TESTS)

test: $(TESTS)
	./$(TESTS)

$(SERVER): $(SERVER_OBJS)
	pushd src && $(CC) $(CFLAGS) $^ -o../$@ && popd

$(CLIENT): $(CLIENT_OBJS)
	pushd src && $(CC) $(CFLAGS) $^ -o../$@ && popd

$(TESTS): $(TESTS_OBJS)
	pushd src && $(CC) $(CFLAGS) $^ -o../$@ && popd

$(SRC)/all_tests.o: src/all_tests.cc  
	pushd src && $(CC) $(CFLAGS) $(TESTS_INC) -c all_tests.cc \
		&& popd

$(HASHLIB)/%.o: $(HASHLIB)/%.cpp
	pushd $(HASHLIB) && $(CC) $(CFLAGS) -I$(HASHLIB) -c $? && popd

$(SRC)/%.o : $(SRC)/linux/%.cc
	$(CC) $(CFLAGS) $(COMMON_INC) -c $< -o $@

$(SRC)/test/%.o : $(SRC)/test/%.cc
	$(CC) $(CFLAGS) $(TESTS_INC) -c $< -o $@

%.o : %.cc
	$(CC) $(CFLAGS) $(COMMON_INC) -c $< -o $@

clean:
	rm -f $(SERVER) $(CLIENT) $(TESTS) src/*.o src/packets/*.o \
		$(HASHLIB)/*.o src/test/*.o 

