#pragma once
#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <WS2tcpip.h>
#include <array>
#include "exception.h"
#include <memory>
#include <vector>

namespace radius {
namespace packets {

class PacketAccessException : public Exception {
  public:
    explicit PacketAccessException(const std::string &message)
        : Exception(message) {}
};
class InvalidPacket : public Exception {
  public:
    explicit InvalidPacket(const std::string &message) : Exception(message) {}
};

unsigned short networkBytes2Short(std::array<byte, 2> bytes);
std::array<byte, 2> short2NetworkBytes(unsigned short s);
}
}
