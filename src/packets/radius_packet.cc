#include "packets/radius_packet.h"
using std::array;
using std::string;
using std::vector;

namespace radius{
    namespace packets{


MessageAuthenticator::MessageAuthenticator() {
    this->buffer.resize(length);
    setType(RadiusAVP::MESSAGE_AUTHENTICATOR);
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

RadiusPacket::RadiusPacket(const vector<byte> &bytes) : buffer(bytes) {
    buffer.resize(getLength());
}
void RadiusPacket::setLength(unsigned short length) {
    array<byte, 2> bytes = short2NetworkBytes(length);
    buffer[2] = bytes[0];
    buffer[3] = bytes[1];
}

short RadiusPacket::getLength() {
    unsigned short l = networkBytes2Short(
        array<byte, 2>({{buffer[2], buffer[3]}}));
    return l;
}

void RadiusPacket::setAuthenticator(
    const array<byte, RadiusPacket::AUTH_LEN> &arr) {
    for (int i = 0; i < AUTH_LEN; i++) {
        buffer[i + 4] = arr[i];
    }
}
array<byte, RadiusPacket::AUTH_LEN> RadiusPacket::getAuthenticator() {
    array<byte, AUTH_LEN> auth;
    copy(buffer.begin() + AUTH_OFFSET,
              buffer.begin() + AUTH_OFFSET + auth.size(), auth.begin());
    return auth;
}

void RadiusPacket::addAVP(const RadiusAVP &avp) {
    buffer.insert(buffer.end(), avp.buffer.begin(), avp.buffer.end());
    setLength(buffer.size());
}
vector<RadiusAVP> RadiusPacket::getAVPList() {
    vector<RadiusAVP> avpList;
    vector<byte> avpListBytes(buffer.begin() + AVP_OFFSET, buffer.end());

    vector<byte>::iterator it = avpListBytes.begin();

    while (it != avpListBytes.end()) {
        byte size = *(it + 1);
        vector<byte> avpBytes(it, it + size);

        RadiusAVP avp(avpBytes);
        avpList.push_back(avp);
        it = it + size;
    }
    return avpList;
}
}}
