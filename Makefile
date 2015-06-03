#Type 'nmake test' for testing
#or simply 'nmake' to build all targets

### Source dirs ###
ROOT=$(MAKEDIR)
SRC=$(ROOT)\src

###  3rd party libraries ###
HASHLIB=$(ROOT)\lib\hash-library
#header-only libraries:
TCLAP=$(ROOT)\lib\tclap-1.2.1\include
CATCH=$(ROOT)\lib\Catch\single_include
SPDLOG=$(ROOT)\lib\spdlog\include
CSV_PARSER=$(ROOT)\fast-cpp-csv-parser\include


### Object dependencies ###
SERVER_OBJS=server.obj md5.obj
CLIENT_OBJS=client.obj md5.obj
TESTS_OBJS=all_tests.obj md5.obj packet.obj \
		  radius_packet.obj eap_packet.obj


### Targets ###
SERVER=server.exe
CLIENT=client.exe
TESTS=all_tests.exe

### Include flags ###
COMMON_INC=/I$(HASHLIB) /I$(TCLAP) /I$(SRC) /I$(SPDLOG)

SERVER_INC=$(COMMON_INC) /I$(CSV_PARSER)
CLIENT_INC=$(COMMON_INC)
TESTS_INC=/I$(HASHLIB) /I$(CATCH) /I$(SRC)

### Other flags ###
CFLAGS = /EHsc


all: $(SERVER) $(CLIENT) $(TESTS)

test: $(TESTS)
	$(TESTS)

$(SERVER): $(SERVER_OBJS)
	$(CC) $(CFLAGS) $**

$(CLIENT): $(CLIENT_OBJS)
	$(CC) $(CFLAGS) $**

$(TESTS): $(TESTS_OBJS)
	$(CC) $(CFLAGS) $**

server.obj: $(SRC)\server.cc
	$(CC) $(CFLAGS) $(SERVER_INC) -c $?

client.obj: $(SRC)\client.cc
	$(CC) $(CFLAGS) $(CLIENT_INC) -c $?

all_tests.obj: $(SRC)\all_tests.cc
	$(CC) $(CFLAGS) $(TESTS_INC) -c $?

clean:
	del *.obj *.exe



### Rules ### 
{$(HASHLIB)}.cpp{}.obj::
	$(CC) $(CFLAGS) /I$(HASHLIB) -c $<

{$(SRC)}.cc{}.obj:
	$(CC) $(CFLAGS) $(COMMON_INC) -c $<

{$(SRC)/packets}.cc{}.obj:
	$(CC) $(CFLAGS) $(COMMON_INC) -c $<

