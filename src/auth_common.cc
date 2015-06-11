#include "auth_common.h"

using radius::packets::RadiusPacket;
using radius::packets::RadiusAVP;
using radius::packets::MessageAuthenticator;

namespace {
// array of 0s
const std::array<byte, 16> nullAuth{};
}

namespace radius {

bool checkMessageAuthenticator(const RadiusPacket &packet,
                               const std::string &secret) {
    RadiusPacket refPacket = packet;
    std::vector<std::unique_ptr<RadiusAVP>> avpList = packet.getAVPList();

    MessageAuthenticator *ma;
    std::for_each(avpList.begin(), avpList.end(),
                  [&](const std::unique_ptr<RadiusAVP> &avp) {
        if (avp->getType() == RadiusAVP::MESSAGE_AUTHENTICATOR) {
            RadiusAVP *ap = const_cast<RadiusAVP *>(avp.get());
            ma = static_cast<MessageAuthenticator *>(ap);
        }
    });

    std::array<byte, 16> md5 = ma->getMd5();

    MessageAuthenticator emptyMa = *ma;
    emptyMa.setMd5(nullAuth);

    refPacket.replaceAVP(*ma, emptyMa);

    return md5HmacBin(refPacket.getBuffer(), secret) == md5;
}

bool checkAuthenticator(const RadiusPacket &packet,
                        const std::array<byte, 16> &authenticator) {
    if (packet.getCode() == RadiusPacket::ACCESS_REQUEST) {
        return true;
    }
    RadiusPacket refPacket(packet);
    refPacket.setAuthenticator(authenticator);
    std::array<byte, 16> md5 = md5Bin(refPacket.getBuffer());
    if (md5 != packet.getAuthenticator()) {
        return false;
    }
    return true;
}
bool checkIntegrity(const RadiusPacket &packet, const std::string &secret,
                    const std::array<byte, 16> &authenticator) {

    return checkAuthenticator(packet, authenticator) &&
           checkMessageAuthenticator(packet, secret);
}
}
