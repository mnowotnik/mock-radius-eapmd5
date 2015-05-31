#include "packets/radius_packet.h"

RadiusPacket::RadiusPacket(const byte inputBuf[], int n) {
    std::vector<byte> tmpBuf(inputBuf,inputBuf+n);
    buffer.insert(buffer.end(),tmpBuf.begin(),tmpBuf.end());
}
