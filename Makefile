

ROOT=$(MAKEDIR)
SRC=$(ROOT)\src

TCLAP=$(ROOT)\lib\tclap-1.2.1\include
HASHLIB=$(ROOT)\lib\hash-library
CATCH=$(ROOT)\lib\Catch\single_include

SERVER_DEP=$(SRC)\server.cc md5.obj
CLIENT_DEP=$(SRC)\client.cc md5.obj
TESTS_DEP=$(SRC)\all_tests.cc md5.obj packet.obj radius_packet.obj eap_packet.obj

SERVER=server.exe
CLIENT=client.exe
TESTS=all_tests.exe

COMMON_INC=/I$(HASHLIB) /I$(TCLAP) /I$(SRC)
SERVER_INC=$(COMMON_INC)
CLIENT_INC=$(COMMON_INC)
TESTS_INC=/I$(HASHLIB) /I$(CATCH) /I$(SRC)

CFLAGS = /EHsc


all: $(SERVER) $(CLIENT) $(TESTS)

test: $(TESTS)
	$(TESTS)

$(SERVER): $(SERVER_DEP)
	$(CC) $(CFLAGS) $(SERVER_INC) $(SERVER_DEP)

$(CLIENT): $(CLIENT_DEP)
	$(CC) $(CFLAGS) $(CLIENT_INC) $(CLIENT_DEP)

$(TESTS): $(TESTS_DEP)
	$(CC) $(CFLAGS) $(TESTS_INC) $(TESTS_DEP)

{$(HASHLIB)}.cpp{}.obj::
	$(CC) $(CFLAGS) /I$(HASHLIB) -c $<

{$(SRC)}.cc{}.obj:
	$(CC) $(CFLAGS) $(COMMON_INC) -c $<

{$(SRC)/packets}.cc{}.obj:
	$(CC) $(CFLAGS) $(COMMON_INC) -c $<

clean:
	del *.obj *.exe
