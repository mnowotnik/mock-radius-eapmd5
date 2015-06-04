#pragma once
#include "packets/common.h"

namespace{
using std::vector;
}

namespace radius{
    namespace packets{

struct Packet{
    const vector<byte> bytes;
    const sockaddr_in addr;

    Packet(const vector<byte> &b,const sockaddr_in &a):bytes(b),
    addr(a){}
};

}}
