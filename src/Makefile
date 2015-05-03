#compiler
CC = g++
#compiler flags
CFLAGS = -lboost_program_options

#build target executable
TARGET = radius_server
#HEADERS = test.hpp server.hpp client.hpp
SOURCE = main.cpp


  all: $(TARGET)

  $(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE)

  clean:
	$(RM) $(TARGET)
