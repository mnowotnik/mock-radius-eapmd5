#pragma once
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <WS2tcpip.h>
#include <array>
#include "exception.h"

namespace radius {
namespace packets {

class PacketAccessException : public Exception {
  public:
    explicit PacketAccessException(const std::string &message)
        : Exception(message) {}
};
class IncorrectPacketSize : public Exception {
  public:
    explicit IncorrectPacketSize(const std::string &message)
        : Exception(message) {}
};

unsigned short networkBytes2Short(std::array<byte, 2> bytes);
std::array<byte, 2> short2NetworkBytes(unsigned short s);
}
}
