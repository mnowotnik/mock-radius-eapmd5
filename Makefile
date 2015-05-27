

ROOT=$(MAKEDIR)
SRC=$(ROOT)\src

TCLAP=$(ROOT)\lib\tclap-1.2.1\include
HASHLIB=$(ROOT)\lib\hash-library
CATCH=$(ROOT)\lib\Catch\single_include

SERVER_DEP=$(SRC)\server.cc md5.obj
CLIENT_DEP=$(SRC)\client.cc md5.obj
TESTS_DEP=$(SRC)\all_tests.cc md5.obj

SERVER=server.exe
CLIENT=client.exe
TESTS=all_tests.exe

COMMON_INC=/I$(HASHLIB) /I$(TCLAP) /I$(SRC)
SERVER_INC=$(COMMON_INC)
CLIENT_INC=$(COMMON_INC)
TESTS_INC=/I$(HASHLIB) /I$(CATCH) /I$(SRC)

all: $(SERVER) $(CLIENT) $(TESTS)

$(SERVER): $(SERVER_DEP)
	$(CC) $(SERVER_INC) $(SERVER_DEP)

$(CLIENT): $(CLIENT_DEP)
	$(CC) $(CLIENT_INC) $(CLIENT_DEP)

$(TESTS): $(TESTS_DEP)
	$(CC) $(TESTS_INC) $(TESTS_DEP)

# $(HASHLIB)\hash-library\%.cc:
# 	$(CC) $@

{$(HASHLIB)}.cpp{}.obj::
	$(CC) /I$(HASHLIB) -c $<

packet.obj: $(SRC)\packet.cc md5.obj
	$(CC) /I$(HASHLIB) /I$(SRC) -c $?

clean:
	del *.obj *.exe
