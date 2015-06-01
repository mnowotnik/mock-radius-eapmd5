#include "packets/radius_packet.h"

MessageAuthenticator::MessageAuthenticator() {
    this->buffer.resize(length);
    setType(RadiusAVP::MESSAGE_AUTHENTICATOR);
}
void MessageAuthenticator::setMd5(const std::array<byte, 16> &md5) {
    std::copy(md5.begin(), md5.end(), buffer.begin() + VAL_OFFSET);
    setLength(buffer.size());
}

std::array<byte, 16> MessageAuthenticator::getMd5() {
    std::array<byte, 16> md5;
    std::copy(buffer.begin() + VAL_OFFSET, buffer.end(), md5.begin());
    return md5;
}

void NasIpAddr::setIp(std::array<byte, 4> ip) {
    buffer.resize(buffer.size() + ip.size());
    std::copy(ip.begin(), ip.end(), buffer.begin() + VAL_OFFSET);
    setLength(buffer.size());
}

void NasIpAddr::setIp(const std::string &ipStr) {
    std::array<byte, 4> ip;
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

void NasIdentifier::setIdentifier(const std::vector<byte> &id) {
    buffer.resize(buffer.size() + id.size());
    std::copy(id.begin(), id.end(), buffer.begin() + VAL_OFFSET);
    setLength(buffer.size());
}
void NasIdentifier::setIdentifier(const std::string &id) {
    std::vector<byte> id_vec(id.begin(), id.end());
    setIdentifier(id_vec);
}

std::string NasIdentifier::getIdentifier() {
    int offset = RadiusAVP::VAL_OFFSET;
    return std::string((const char *)&buffer[offset], buffer.size() - offset);
}

RadiusPacket::RadiusPacket(const std::vector<byte> &bytes) : buffer(bytes) {
    buffer.resize(getLength());
}
void RadiusPacket::setLength(unsigned short length) {
    std::array<byte, 2> bytes = radius::internal::short2NetworkBytes(length);
    buffer[2] = bytes[0];
    buffer[3] = bytes[1];
}

short RadiusPacket::getLength() {
    unsigned short l = radius::internal::networkBytes2Short(
        std::array<byte, 2>({{buffer[2], buffer[3]}}));
    return l;
}

void RadiusPacket::setAuthenticator(
    const std::array<byte, RadiusPacket::AUTH_LEN> &arr) {
    for (int i = 0; i < AUTH_LEN; i++) {
        buffer[i + 4] = arr[i];
    }
}
std::array<byte, RadiusPacket::AUTH_LEN> RadiusPacket::getAuthenticator() {
    std::array<byte, AUTH_LEN> auth;
    std::copy(buffer.begin() + AUTH_OFFSET,
              buffer.begin() + AUTH_OFFSET + auth.size(), auth.begin());
    return auth;
}

void RadiusPacket::addAVP(const RadiusAVP &avp) {
    buffer.insert(buffer.end(), avp.buffer.begin(), avp.buffer.end());
    setLength(buffer.size());
}
std::vector<RadiusAVP> RadiusPacket::getAVPList() {
    std::vector<RadiusAVP> avpList;
    std::vector<byte> avpListBytes(buffer.begin() + AVP_OFFSET, buffer.end());

    std::vector<byte>::iterator it = avpListBytes.begin();

    while (it != avpListBytes.end()) {
        byte size = *(it + 1);
        std::vector<byte> avpBytes(it, it + size);

        RadiusAVP avp(avpBytes);
        avpList.push_back(avp);
        it = it + size;
    }
    return avpList;
}
