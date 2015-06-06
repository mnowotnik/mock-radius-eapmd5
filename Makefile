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
COMMON_OBJS=packets\radius_packet.obj packets\eap_packet.obj logging.obj \
			$(HASHLIB)\md5.obj packets\common.obj auth_common.obj 
SERVER_OBJS=server.obj server_loop.obj $(COMMON_OBJS)
CLIENT_OBJS=client.obj $(COMMON_OBJS)
TESTS_OBJS=all_tests.obj test\radius_server_test.obj test\logging_test.obj \
		   test\server_loop_test.obj  test\packet_test.obj test\auth_common_test.obj \
		   radius_server.obj server_loop.obj \
		   $(COMMON_OBJS)



### Targets ###
SERVER=server.exe
CLIENT=client.exe
TESTS=all_tests.exe

### Include flags ###
COMMON_INC=/I$(HASHLIB) /I$(TCLAP) /I$(SRC) /I$(SPDLOG)

SERVER_INC=$(COMMON_INC) /I$(CSV_PARSER)
CLIENT_INC=$(COMMON_INC)
TESTS_INC=/I$(HASHLIB) /I$(CATCH) /I$(SRC) /I$(SPDLOG)

### Other flags ###
CFLAGS = /EHsc /MP


all: $(SERVER) $(CLIENT) $(TESTS)

test: $(TESTS)
	$(TESTS)

$(SERVER): $(SERVER_OBJS)
	pushd $(SRC) & $(CC) $(CFLAGS) /Fe..\$@ $** & popd

$(CLIENT): $(CLIENT_OBJS)
	pushd $(SRC) & $(CC) $(CFLAGS) /Fe..\$@ $** & popd

$(TESTS): $(TESTS_OBJS)
	pushd $(SRC) & $(CC) $(CFLAGS) /Fe..\$@ $** & popd

server.obj: $(SRC)\server.cc
	pushd $(SRC) & $(CC) $(CFLAGS) $(SERVER_INC) -c $? \
		& popd

client.obj: $(SRC)\client.cc
	pushd $(SRC) & $(CC) $(CFLAGS) $(CLIENT_INC) -c $? \
		& popd

all_tests.obj: $(SRC)\all_tests.cc
	pushd $(SRC) & $(CC) $(CFLAGS) $(TESTS_INC) -c $? \
		& popd

clean:
	del *.obj *.exe $(SRC)\*.obj $(SRC)\packets\*.obj \
		$(HASHLIB)\*.obj $(SRC)\test\*.obj



### Rules ### 
{$(HASHLIB)}.cpp{$(HASHLIB)}.obj::
	pushd $(HASHLIB) & $(CC) $(CFLAGS) /I$(HASHLIB) -c $< & popd

{$(SRC)}.cc{}.obj:
	pushd $(SRC) & $(CC) $(CFLAGS) $(COMMON_INC) -c $< & popd

{$(SRC)\packets}.cc{packets}.obj:
	pushd $(SRC)\packets & $(CC) $(CFLAGS) $(COMMON_INC) -c $< & popd

{$(SRC)\test}.cc{test}.obj:
	pushd $(SRC)\test & $(CC) $(CFLAGS) $(TESTS_INC) -c $< & popd

