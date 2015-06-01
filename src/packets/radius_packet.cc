#include "packets/radius_packet.h"

MessageAuthenticator::MessageAuthenticator() {
  this->buffer.resize(length);
  setType(RadiusAVP::MESSAGE_AUTHENTICATOR);
}
void MessageAuthenticator::setMd5(const std::array<byte, 16> &md5) {
  int offset = RadiusAVP::VAL_OFFSET;
  buffer.insert(buffer.begin() + offset, md5.begin(), md5.end());
  setLength(buffer.size());
}

std::array<byte, 16> MessageAuthenticator::getMd5() {
  std::array<byte, 16> md5;
  int offset = RadiusAVP::VAL_OFFSET;
  std::copy(buffer.begin() + offset, buffer.begin() + offset + length,
            md5.begin());
  return md5;
}

void NasIpAddr::setIp(std::array<byte, 4> ip) {
  buffer.insert(buffer.begin() + RadiusAVP::VAL_OFFSET, ip.begin(), ip.end());
  setLength(length);
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

void NasIdentifier::setIdentifier(std::vector<byte> id) {
  buffer.insert(buffer.begin() + RadiusAVP::VAL_OFFSET, id.begin(), id.end());
  setLength(buffer.size());
}

std::string NasIdentifier::getIdentifier() {
  int offset = RadiusAVP::VAL_OFFSET;
  return std::string((const char *)&buffer[offset], buffer.size() - offset);
}

RadiusPacket::RadiusPacket(const byte inputBuf[], int n) {
  std::vector<byte> tmpBuf(inputBuf, inputBuf + n);
  buffer.insert(buffer.end(), tmpBuf.begin(), tmpBuf.end());
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

void RadiusPacket::setAuthenticator(const std::array<byte, 16> &arr) {
  for (int i = 0; i < 16; i++) {
    buffer[i + 4] = arr[i];
  }
}
std::array<byte, 16> RadiusPacket::getAuthenticator() {
  std::array<byte, 16> auth;
  std::copy(buffer.begin() + 4, buffer.begin() + 4 + auth.size(), auth.begin());
  return auth;
}

void RadiusPacket::addAVP(const RadiusAVP &avp) {
  buffer.insert(buffer.end(), avp.buffer.begin(), avp.buffer.end());
}
std::vector<RadiusAVP> RadiusPacket::getAVPList() {
  std::vector<RadiusAVP> avpList;

  // TODO
  return avpList;

}
