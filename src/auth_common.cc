#include "auth_common.h"

using radius::packets::RadiusPacket;
using radius::packets::RadiusAVP;
using radius::packets::MessageAuthenticator;


namespace{
    //array of 0s
    const std::array<byte,16>nullAuth{};

}

namespace radius{

    bool checkMessageAuth(const RadiusPacket &packet,const std::string &secret){
        RadiusPacket refPacket(packet.getBufferWoAVP());
        std::vector<RadiusAVP> avpList = packet.getAVPList();
        

        MessageAuthenticator*ma;
        std::for_each(avpList.begin(),avpList.end(),[&](const RadiusAVP&avp){
                if(avp.getType() == RadiusAVP::MESSAGE_AUTHENTICATOR){
                RadiusAVP *ap = const_cast<RadiusAVP*>(&avp);
                ma=static_cast<MessageAuthenticator*>(ap);
                }
                });

        std::array<byte,16>md5 = ma->getMd5();
        ma->setMd5(nullAuth);

        std::for_each(avpList.begin(),avpList.end(),
                [&](const RadiusAVP&avp){refPacket.addAVP(avp);});

        return crypto::md5Bin(refPacket.getBuffer()) == md5;
    }
    bool checkIntegrity(const RadiusPacket &packet,
            const std::string &secret,
            const std::vector<byte>&authenticator){
    
        return false;
    
    }


}
