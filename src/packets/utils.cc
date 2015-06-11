#include "packets/utils.h"
#include <iostream>

namespace radius{
namespace packets{
EapPacket extractEapPacket(const RadiusPacket& radiusPacket){
    std::vector<byte>buffer;

    for(const auto& avpPtr : radiusPacket.getAVPList()){
        if(avpPtr->getType() == RadiusAVP::EAP_MESSAGE){
            std::vector<byte>avpVal = avpPtr -> getValue();
            buffer.insert(buffer.end(),avpVal.begin(),avpVal.end());
        }
    }

    if(buffer.size()==0){
        throw InvalidPacket("extractEapPacket. The input packet does not contain"
                " any EapMessage AVP");
    }
    return EapPacket(buffer);
}
}}
