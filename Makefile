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
COMMON_OBJS=$(SRC)\packets\radius_packet.obj $(SRC)\packets\eap_packet.obj $(SRC)\logging.obj \
			$(HASHLIB)\md5.obj $(SRC)\packets\common.obj $(SRC)\auth_common.obj 

SERVER_OBJ=$(SRC)\server.obj $(SRC)\server_loop.obj $(COMMON_OBJS)

CLIENT_OBJS=$(SRC)\client.obj $(COMMON_OBJS)
	
TESTS_OBJS=$(SRC)\all_tests.obj $(SRC)\test\radius_server_test.obj $(SRC)\test\logging_test.obj \
		   $(SRC)\test\server_loop_test.obj  $(SRC)\test\packet_test.obj $(SRC)\test\auth_common_test.obj \
		   $(SRC)\radius_server.obj $(SRC)\server_loop.obj \
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

$(SRC)\server.obj: $(SRC)\server.cc
	pushd $(SRC) & $(CC) $(CFLAGS) $(SERVER_INC) -c $? \
		& popd

$(SRC)\client.obj: $(SRC)\client.cc
	pushd $(SRC) & $(CC) $(CFLAGS) $(CLIENT_INC) -c $? \
		& popd

$(SRC)\all_tests.obj: $(SRC)\all_tests.cc
	pushd $(SRC) & $(CC) $(CFLAGS) $(TESTS_INC) -c $? \
		& popd

clean:
	del *.obj *.exe $(SRC)\*.obj $(SRC)\packets\*.obj \
		$(HASHLIB)\*.obj $(SRC)\test\*.obj



### Rules ### 
{$(HASHLIB)}.cpp{$(HASHLIB)}.obj::
	pushd $(HASHLIB) & $(CC) $(CFLAGS) /I$(HASHLIB) -c $< & popd

{$(SRC)}.cc{$(SRC)}.obj:
	pushd $(SRC) & $(CC) $(CFLAGS) $(COMMON_INC) -c $< & popd

{$(SRC)\packets}.cc{$(SRC)\packets}.obj:
	pushd $(SRC)\packets & $(CC) $(CFLAGS) $(COMMON_INC) -c $< & popd

{$(SRC)\test}.cc{$(SRC)\test}.obj:
	pushd $(SRC)\test & $(CC) $(CFLAGS) $(TESTS_INC) -c $< & popd

