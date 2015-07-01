SHELL := /bin/bash
#Type 'make test' for testing
#or simply 'make' to build all targets

CC=g++
ROOT=$(CURDIR)
SRC=$(ROOT)/src


###  3rd party libraries ###
HASHLIB=$(ROOT)/lib/hash-library
#header-only libraries:
TCLAP=$(ROOT)/lib/tclap-1.2.1/include
CATCH=$(ROOT)/lib/Catch/single_include
SPDLOG=$(ROOT)/lib/spdlog/include
CSV_PARSER=$(ROOT)/lib/fast-cpp-csv-parser/include


### Object dependencies ###
COMMON_OBJS=$(SRC)/packets/radius_packet.o $(SRC)/packets/eap_packet.o $(SRC)/logging.o \
			$(HASHLIB)/md5.o $(SRC)/packets/common.o $(SRC)/auth_common.o $(SRC)/crypto.o \
			$(SRC)/packets/utils.o $(SRC)/csv_reader.o $(HASHLIB)/crc32.o $(HASHLIB)/sha1.o \
			$(HASHLIB)/sha3.o $(HASHLIB)/sha256.o

SERVER_OBJS=$(SRC)/server.o $(SRC)/server_net.o $(SRC)/radius_server.o $(COMMON_OBJS)

CLIENT_OBJS=$(SRC)/client.o $(SRC)/client_net.o $(SRC)/interactive.o  $(COMMON_OBJS)

TESTS_OBJS=$(SRC)/all_tests.o $(SRC)/test/radius_server_test.o $(SRC)/test/logging_test.o \
		   $(SRC)/test/server_net_test.o $(SRC)/test/packet_test.o $(SRC)/test/auth_common_test.o $(SRC)/test/csv_test.o \
		   $(SRC)/test/crypto_test.o  $(SRC)/radius_server.o $(SRC)/server_net.o  \
		   $(COMMON_OBJS)

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
# -D_WIN32_WINNT=0x600


all: $(SERVER) $(CLIENT) $(TESTS)

test: $(TESTS)
	./$(TESTS)

$(SERVER): $(SERVER_OBJS)
	pushd src && $(CC) $(CFLAGS) $? -o../$@ && popd

$(CLIENT): $(CLIENT_OBJS)
	pushd src && $(CC) $(CFLAGS) $? -o../$@ && popd

$(TESTS): $(TESTS_OBJS)
	pushd src && $(CC) $(CFLAGS) $? -o../$@ && popd

$(SRC)/all_tests.o: src/all_tests.cc  
	pushd src && $(CC) $(CFLAGS) $(TESTS_INC) -c all_tests.cc \
		&& popd

clean:
	rm src/*.o src/packets/*.o \
		$(HASHLIB)/*.o src/test/*.o 



# ### Rules ###
# {$(HASHLIB)}.cpp{$(HASHLIB)}.o::
# 	pushd $(HASHLIB) & $(CC) $(CFLAGS) /I$(HASHLIB) -c $< & popd
#
$(HASHLIB)/%.o: $(HASHLIB)/%.cpp
	pushd $(HASHLIB) && $(CC) $(CFLAGS) -I$(HASHLIB) -c $? && popd

$(SRC)/server_net.o : $(SRC)/linux/server_net.cc 
	$(CC) $(CFLAGS) $(COMMON_INC) -c $< -o $@


$(SRC)/test/%.o : $(SRC)/test/%.cc
	$(CC) $(CFLAGS) $(TESTS_INC) -c $< -o $@

%.o : %.cc
	$(CC) $(CFLAGS) $(COMMON_INC) -c $< -o $@

# server.o : server.cc
# 	$(CC) $(CFLAGS) $(COMMON_INC) $< -o $@

# {packets}.cc{packets}.o:
# 	pushd packets & $(CC) $(CFLAGS) $(COMMON_INC) -c $< & popd

# {test}.cc{test}.o:
# 	pushd test & $(CC) $(CFLAGS) $(TESTS_INC) -c $< & popd

