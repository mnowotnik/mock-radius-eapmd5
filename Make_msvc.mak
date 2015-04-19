

SOURCES=hello.cc

all: hello.exe

hello.exe: $(SOURCES)
	$(CC) $(SOURCES)

clean:
	del *.o *.exe
