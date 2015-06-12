#include "packets/radius_packet.h"
#include <iostream>
using std::array;
using std::string;
using std::vector;

namespace radius {
namespace packets {

namespace {
typedef std::unique_ptr<RadiusAVP> RadiusAVPPtr;
}

MessageAuthenticator::MessageAuthenticator() {
    this->buffer.resize(LENGTH);
    setType(RadiusAVP::MESSAGE_AUTHENTICATOR);
    setLength(buffer.size());
}
void MessageAuthenticator::setMd5(const array<byte, 16> &md5) {
    copy(md5.begin(), md5.end(), buffer.begin() + VAL_OFFSET);
    setLength(buffer.size());
}

array<byte, 16> MessageAuthenticator::getMd5() {
    array<byte, 16> md5;
    copy(buffer.begin() + VAL_OFFSET, buffer.end(), md5.begin());
    return md5;
}

void NasIpAddr::setIp(array<byte, 4> ip) {
    buffer.resize(buffer.size() + ip.size());
    copy(ip.begin(), ip.end(), buffer.begin() + VAL_OFFSET);
    setLength(buffer.size());
}

void NasIpAddr::setIp(const string &ipStr) {
    array<byte, 4> ip;
    in_addr addr;
    inet_pton(AF_INET, ipStr.c_str(), &addr);
    memcpy((void *)&ip[0], &addr, sizeof(in_addr));
    setIp(ip);
}

in_addr NasIpAddr::getIp() {
    byte *addrPtr = &buffer[RadiusAVP::VAL_OFFSET];
    struct in_addr addr;
    /* inet_ntop(AF_INET,&addr,ipStr.c_str(),ipStr.length()); */
    memcpy((void *)&addr, addrPtr, sizeof(in_addr));
    return addr;
}

void NasIdentifier::setIdentifier(const vector<byte> &id) {
    buffer.resize(buffer.size() + id.size());
    copy(id.begin(), id.end(), buffer.begin() + VAL_OFFSET);
    setLength(buffer.size());
}
void NasIdentifier::setIdentifier(const string &id) {
    vector<byte> id_vec(id.begin(), id.end());
    setIdentifier(id_vec);
}

string NasIdentifier::getIdentifier() {
    int offset = RadiusAVP::VAL_OFFSET;
    return string((const char *)&buffer[offset], buffer.size() - offset);
}

void MessageAuthenticator::validate() {
    if (buffer.size() != LENGTH) {
        throw InvalidPacket("The Message Authenticator length is incorrect"
                "("+std::to_string(buffer.size())+")");
    }
}

void EapMessage::validate() {
    if (buffer.size() < MIN_LENGTH) {
        throw InvalidPacket("An EAP-Message length is too small"
                "("+std::to_string(buffer.size())+")");
    }
}

void NasIdentifier::validate() {}

void NasIpAddr::validate() {
    if (buffer.size() != LENGTH) {
        throw InvalidPacket("The NAS-IP-Address length is incorrect"
                "("+std::to_string(buffer.size())+")");
    }
}

RadiusPacket::RadiusPacket(const vector<byte> &bytes) : buffer(bytes) {
    if (getLength() < bytes.size()) {
        buffer.resize(getLength());
    }
    validate();
}
void RadiusPacket::setLength(unsigned short length) {
    array<byte, 2> bytes = short2NetworkBytes(length);
    buffer[2] = bytes[0];
    buffer[3] = bytes[1];
}

short RadiusPacket::getLength() const {
    unsigned short l =
        networkBytes2Short(array<byte, 2>({{buffer[2], buffer[3]}}));
    return l;
}

void
RadiusPacket::setAuthenticator(const array<byte, RadiusPacket::AUTH_LEN> &arr) {
    for (int i = 0; i < AUTH_LEN; i++) {
        buffer[i + 4] = arr[i];
    }
}
array<byte, RadiusPacket::AUTH_LEN> RadiusPacket::getAuthenticator() const {
    array<byte, AUTH_LEN> auth;
    copy(buffer.begin() + AUTH_OFFSET,
         buffer.begin() + AUTH_OFFSET + auth.size(), auth.begin());
    return auth;
}

void RadiusPacket::addAVP(const RadiusAVP &avp) {
    buffer.insert(buffer.end(), avp.buffer.begin(), avp.buffer.end());
    setLength(buffer.size());
}

std::vector<byte> RadiusPacket::getBufferWoAVP() const {
    vector<byte> bytes(buffer.begin(), buffer.begin() + AVP_OFFSET);
    return bytes;
}
vector<std::unique_ptr<RadiusAVP>> RadiusPacket::getAVPList() const {
    vector<std::unique_ptr<RadiusAVP>> avpList;
    vector<byte> avpListBytes(buffer.begin() + AVP_OFFSET, buffer.end());

    vector<byte>::iterator it = avpListBytes.begin();

    while (it != avpListBytes.end()) {
        byte size = *(it + 1);
        vector<byte> avpBytes(it, it + size);

        avpList.emplace_back(RadiusAVP::factoryFun(avpBytes));
        it = it + size;
    }
    return avpList;
}

std::vector<byte>::iterator RadiusPacket::findAVP(const RadiusAVP &avp) {
    return std::search(buffer.begin(), buffer.end(), avp.buffer.begin(),
                       avp.buffer.end());
}

bool RadiusPacket::removeAVP(const RadiusAVP &avp) {
    if (avp.buffer.size() == 0) {
        return false;
    }
    auto it = findAVP(avp);
    if (it == buffer.end()) {
        return false;
    }
    buffer.erase(it, it + avp.buffer.size());
    setLength(buffer.size());
    return true;
}
bool RadiusPacket::replaceAVP(const RadiusAVP &oldAVP,
                              const RadiusAVP &newAVP) {
    auto itBeg = findAVP(oldAVP);

    if (itBeg == buffer.end()) {
        std::cout << "here" << std::endl;
    }
    if (itBeg == buffer.begin() || itBeg == buffer.end()) {
        return false;
    }
    auto itIns = buffer.erase(itBeg, itBeg + oldAVP.buffer.size());
    buffer.insert(itIns, newAVP.buffer.begin(), newAVP.buffer.end());
    setLength(buffer.size());
    return true;
}

void RadiusPacket::validate() {
    unsigned short len = getLength();
    if (len < MIN_LENGTH){
        throw InvalidPacket("The length field value ("+std::to_string(len)+")" 
               "is too small");
    }
    if (len != buffer.size()) {
        throw InvalidPacket("The length field value ("+std::to_string(len)+")"
                " is not equal to packet size("+std::to_string(buffer.size())+")" );
    }
    if (getLength() == MIN_LENGTH) {
        return;
    }

    auto it = buffer.begin() + AVP_OFFSET;

    while (it != buffer.end()) {
        if (it + 1 == buffer.end()) {
            throw InvalidPacket("Unrecognized byte at the position: "
                    + std::to_string((buffer.begin()-it)));
        }
        byte size = *(it + 1);
        if (it + size > buffer.end()) {
        throw InvalidPacket("The packet is too short. Should be: "+ std::to_string((it+size-buffer.begin()))+
            " Is: "+std::to_string(buffer.size())+ ". According to AVP size at "+std::to_string((it+1-buffer.begin()))); 
        }
        if (size <= RadiusAVP::MIN_SIZE) {
            throw InvalidPacket("The AVP size value is incorrect (<"+
                    std::to_string(RadiusAVP::MIN_SIZE)+") at "+std::to_string((it+1-buffer.begin())));
        }
        it = it + size;
    }

    for (const auto &avpPtr : getAVPList()) {
        avpPtr->validate();
    }
}

RadiusAVP *RadiusAVP::factoryFun(const std::vector<byte> &bytes) {
    if (bytes.size() < MIN_SIZE) {
        throw InvalidPacket(
            "RadiusAVP::factoryFun. Invalid input buffer. Too small.");
    }
    byte type = bytes[0];

    RadiusAVP *avp;
    switch (type) {
    case MESSAGE_AUTHENTICATOR:
        avp = new MessageAuthenticator(bytes);
        break;
    case EAP_MESSAGE:
        avp = new EapMessage(bytes);
        break;
    case NAS_IP_ADDRESS:
        avp = new NasIpAddr(bytes);
        break;
    case NAS_IDENTIFIER:
        avp = new NasIdentifier(bytes);
        break;
    default:
        throw InvalidPacket("Unsupported type : " + (int)type);
    }
    return avp;
}

std::ostream &operator<<(std::ostream &o, const RadiusPacket &packet) {
    std::string ind1(4, ' ');
    o << "1 Code = " + std::to_string(packet.getCode()) + '(' +
             packet.codeStr() + ')' + '\n';
    o << "1 ID = " + std::to_string(packet.getIdentifier()) + '\n';
    o << "2 Length = " + std::to_string(packet.getLength()) + '\n';
    o << "16 Authenticator\n";
    std::vector<std::unique_ptr<RadiusAVP>> avps = packet.getAVPList();
    o << "Attributes:\n";
    if (avps.size() == 0) {
        o << ind1 + "None\n";
    }
    for (const auto &avpPtr : avps) {
        o << ind1;
        o << *avpPtr;
        o << '\n';
    }

    return o;
}
std::string RadiusPacket::codeStr() const {
    int code = getCode();
    switch (code) {
    case ACCESS_REQUEST:
        return "Access-Request";
    case ACCESS_ACCEPT:
        return "Access-Accept";
    case ACCESS_REJECT:
        return "Access-Reject";
    case 4:
        return "Accounting-Request";
    case 5:
        return "Accounting-Response";
    case ACCESS_CHALLENGE:
        return "Access-Challenge";
    case 12:
        return "Status-Server (experimental)";
    case 13:
        return "Status-Client (experimental)";
    default:
        return "reserved";
    }
}
}
}
