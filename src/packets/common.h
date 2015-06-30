#ifndef COMMON_H_R7FUUXGQ
#define COMMON_H_R7FUUXGQ

#include <array>
#include <memory>
#include <vector>
#include "exception.h"
#include "typedefs.h"
#include "sockets.h"

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
#endif /* end of include guard: COMMON_H_R7FUUXGQ */
