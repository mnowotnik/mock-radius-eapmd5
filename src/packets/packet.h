#pragma once
#include "packets/common.h"
#include <vector>

namespace radius{
    namespace packets{

struct Packet{
    const std::vector<byte> bytes;
    const sockaddr_in addr;

    Packet(const std::vector<byte> &b,const sockaddr_in &a):bytes(b),
    addr(a){}

};

}}
