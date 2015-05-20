

ROOT=$(MAKEDIR)
SRC=$(ROOT)\src

TCLAP=$(ROOT)\lib\tclap-1.2.1\include
HASHLIB=$(ROOT)\lib\hash-library

SERVER_SRC=$(SRC)\server.cc
CLIENT_SRC=$(SRC)\client.cc 
TESTS_SRC=$(SRC)\all_tests.cc

SERVER=server.exe
CLIENT=client.exe
TESTS=all_tests.exe

COMMON_INC=/I$(HASHLIB) /I$(TCLAP) /I$(SRC)
COMMON_OBJ=md5.obj
SERVER_INC=$(COMMON_INC)
CLIENT_INC=$(COMMON_INC)

all: $(SERVER) $(CLIENT) $(TESTS)

$(SERVER): $(SERVER_SRC)
	$(CC) $(SERVER_INC) $(SERVER_SRC)

$(CLIENT): $(CLIENT_SRC) $(COMMON_OBJ)
	$(CC) $(CLIENT_INC) $(CLIENT_SRC) $(COMMON_OBJ)

$(TESTS): $(TESTS_SRC)
	$(CC) $(TESTS_SRC)

$(HASHLIB)\hash-library\%.cc:
	$(CC) $@

{$(HASHLIB)}.cpp{}.obj::
	$(CC) /I$(HASHLIB) -c $<

clean:
	del *.obj *.exe
