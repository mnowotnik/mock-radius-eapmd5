#include "radius_server.h"
using std::map;
using std::string;
using std::vector;
using radius::packets::Packet;
using radius::packets::RadiusPacket;
using radius::packets::EapPacket;
using radius::packets::EapIdentity;
using radius::packets::EapData;
using radius::packets::EapMd5Challenge;
using radius::packets::RadiusAVP;
using radius::packets::EapMessage;
using radius::AuthMode;

namespace radius {

namespace {
const int MIN_CHAL_VAL = 12;
const int MAX_CHAL_VAL = 24;

std::unique_ptr<packets::RadiusPacket>
prepareAccessChal(RadiusPacket &req, EapMessage &eapM,
                  const std::string secret) {
    std::unique_ptr<packets::RadiusPacket> accessChal(new RadiusPacket);
    accessChal->setCode(RadiusPacket::ACCESS_CHALLENGE);
    accessChal->setIdentifier(req.getIdentifier() + 1);
    accessChal->addAVP(dynamic_cast<const RadiusAVP &>(eapM));
    accessChal->setAuthenticator(req.getAuthenticator());
    calcAndSetMsgAuth(*accessChal, secret);
    calcAndSetAuth(*accessChal);
    return accessChal;
}
}

RadiusServer::RadiusServer(const map<string, string> &userPassMap,
                           const string &secret, const Logger &logger,
                           AuthMode authMode)
    : userPassMap(userPassMap), secret(secret), logger(logger),
      authMode(authMode) {}

const vector<Packet> RadiusServer::processPacket(const Packet &packet) {
    logger->info() << "Incoming RADIUS packet";

    vector<Packet> packetsToSend;

    try {
        RadiusPacket radiusPacket(packet.bytes);
        logger->info() << NL << radiusPacket;

        if (!isValid(radiusPacket)) {
            logger->trace() << "Input packet has invaild structure. Requires "
                               "only one Message Authenticator and " << NL
                            << "at least one EAP-Message";
            return addPendingPackets(packetsToSend);
        }

        if (!isRequest(radiusPacket)) {
            logger->trace()
                << "Packet has wrong type. Is not an Access-Request";
            return addPendingPackets(packetsToSend);
        }

        if (!checkIntegrity(radiusPacket, secret)) {
            logger->trace()
                << "Message Authenticator checksum does not match the packet";
            return addPendingPackets(packetsToSend);
        }

        EapPacket eapPacket(extractEapPacket(radiusPacket));
        logger->info() << "Encapsulated EAP packet:" << NL << eapPacket;

        std::unique_ptr<EapData> eapDataPtr(eapPacket.getData());
        byte eapDataT = eapDataPtr->getType();

        if (eapDataT == EapData::IDENTITY) {
            EapIdentity &eapIden =
                *dynamic_cast<EapIdentity *>(eapDataPtr.get());
            RadiusPacketPtr radiusPacketPtr =
                recvEapId(radiusPacket, eapIden, packet.addr);
            if (radiusPacketPtr.get()) {
                packetsToSend.push_back(
                    Packet(radiusPacketPtr->getBuffer(), packet.addr));
            }
        } else if (eapDataT == EapData::MD5_CHALLENGE) {
            RadiusPacketPtr rPtr = recvEapMd5Chal(
                    radiusPacket,
                    *dynamic_cast<EapMd5Challenge*>(eapDataPtr.get()),
                            eapPacket.getIdentifier());
            Packet packetToSend(rPtr->getBuffer(), packet.addr);
            packetsToSend.push_back(packetToSend);
        }
    } catch (const packets::InvalidPacket &e) {
        logger->trace() << "Packet invalid. Reason : " << NL << e.what();
        logger->trace() << "Packet dump: " << NL
                        << packet2LogBytes(packet.bytes);
        return addPendingPackets(packetsToSend);
    }
    return addPendingPackets(packetsToSend);
}

RadiusServer::RadiusPacketPtr RadiusServer::recvEapMd5Chal(RadiusPacket &radiusPacket,
        EapMd5Challenge &eapMd5, byte eapId){

    std::vector<byte> md5RespVec = eapMd5.getValue();
    std::array<byte, 16> md5RespArr;
    std::copy(md5RespVec.begin(), md5RespVec.end(), md5RespArr.begin());

    std::array<byte, 16> md5RespArrRef =
        calcChalVal(eapId, persistChal->challenge,
                *persistPass);

    EapPacket respEapPacket;
    RadiusPacketPtr respPacket(new RadiusPacket);
    if (md5RespArrRef == md5RespArr) {
        respEapPacket.setType(EapPacket::SUCCESS);
        respPacket->setCode(RadiusPacket::ACCESS_ACCEPT);
    } else {
        respEapPacket.setType(EapPacket::FAILURE);
        respPacket->setCode(RadiusPacket::ACCESS_REJECT);
    }
    respEapPacket.setIdentifier(eapId);
    respPacket->setIdentifier(radiusPacket.getIdentifier());

    EapMessage eapM;
    eapM.setValue(respEapPacket.getBuffer());
    respPacket->addAVP(dynamic_cast<const RadiusAVP &>(eapM));
    respPacket->setAuthenticator(radiusPacket.getAuthenticator());
    calcAndSetMsgAuth(*respPacket, secret);
    calcAndSetAuth(*respPacket);

    return respPacket;
}

RadiusServer::RadiusPacketPtr
RadiusServer::recvEapId(RadiusPacket &radiusPacket, EapIdentity &eapIden,
                        const sockaddr_in &inAddr) {
    std::string userName = eapIden.getIdentity();
    const auto passIt = userPassMap.find(userName);
    if (passIt == userPassMap.end()) {
        logger->trace() << "Username " + userName + " not found";
        return RadiusPacketPtr(nullptr);
    }
    persistPass.reset(new std::string(passIt->second)); // TODO

    // prepare EAP packet
    EapPacket eapReq;
    eapReq.setType(EapPacket::REQUEST);
    // initial identifier is the same as in the radius packet
    // arbitrary decision
    eapReq.setIdentifier(radiusPacket.getIdentifier());

    // prepare MD5 challenge
    std::vector<byte> challenge =
        generateRandomBytes(MIN_CHAL_VAL, MAX_CHAL_VAL);
    EapMd5Challenge md5Chal;
    md5Chal.setValue(challenge);
    eapReq.setData(dynamic_cast<const EapData &>(md5Chal));
    EapMessage eapM;
    eapM.setValue(eapReq.getBuffer());

    // add unique challenge to map and await reponse
    persistChallenge(userName, inAddr, eapReq.getIdentifier(), challenge);

    persistChal.reset(new AuthData(challenge));

    // prepare RADIUS Acess-Challenge packet
    return prepareAccessChal(radiusPacket, eapM, secret);
}

void RadiusServer::persistChallenge(const std::string &userName,
                                    const sockaddr_in &inAddr, byte msgId,
                                    std::vector<byte> &challenge) {
    AuthRequestId authId(userName, inAddr, msgId);
    authProcMap.insert(std::make_pair(authId, AuthData(challenge)));
}

const vector<Packet>
RadiusServer::addPendingPackets(vector<Packet> packetsToSend) {
    std::transform(pendingPackets.begin(), pendingPackets.end(),
                   std::back_inserter(packetsToSend),
                   [](const PendingPacket &p) { return p.packet; });
    return packetsToSend;
}

void RadiusServer::updatePending() {
    std::for_each(pendingPackets.begin(), pendingPackets.end(),
                  [](PendingPacket &p) { p.counter++; });

    for (auto it = pendingPackets.begin(); it != pendingPackets.end();) {
        if (it->counter > PENDING_LIMIT) {
            it = pendingPackets.erase(it);
        } else {
            ++it;
        }
    }
}
}
