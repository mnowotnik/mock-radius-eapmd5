#ifndef PACKET_H_IEFLGARB
#define PACKET_H_IEFLGARB

#include "packets/common.h"
#include <vector>

namespace radius {
namespace packets {

struct Packet {
    std::vector<byte> bytes;
    sockaddr_in addr;

    Packet(const std::vector<byte> &b, const sockaddr_in &a)
        : bytes(b), addr(a) {}
};
}
}


#endif /* end of include guard: PACKET_H_IEFLGARB */
