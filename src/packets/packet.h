#pragma once
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <WS2tcpip.h>
#include <iostream>
#include <array>
#include <vector>
#include <string>
#include <vector>
#include "crypto.h"
#include "exception.h"

typedef unsigned __int8 byte;


class PacketAccessException: public Exception {
    public:
    explicit PacketAccessException(const std::string& message): Exception(message) {}
};
class IncorrectPacketSize: public Exception {
    public:
    explicit IncorrectPacketSize(const std::string& message): Exception(message) {}
};

namespace radius {
namespace internal {
unsigned short networkBytes2Short(std::array<byte, 2> bytes);
std::array<byte, 2> short2NetworkBytes(unsigned short s);
}
}

