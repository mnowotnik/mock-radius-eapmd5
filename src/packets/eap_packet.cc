#include "packets/eap_packet.h"

void EapIdentity::setIdentity(const std::string &identity) {
  buffer.insert(buffer.begin() + DATA_OFFSET, identity.begin(), identity.end());
}

std::string EapIdentity::getIdentity() {
  return std::string((const char *)&(buffer[DATA_OFFSET]),
                     buffer.size() - DATA_OFFSET);
}

void EapMd5Challenge::setValue(const std::vector<byte> &value) {
  buffer.insert(buffer.begin() + VAL_OFFSET, value.begin(), value.end());
  setValueSize(value.size());
}

std::vector<byte> EapMd5Challenge::getValue() {
  std::vector<byte>::iterator itEnd =
      buffer.begin() + DATA_OFFSET + getValueSize();
  return std::vector<byte>(buffer.begin() + DATA_OFFSET, itEnd);
}

void EapMd5Challenge::setName(const std::string &name) {
  int offset = VAL_OFFSET + getValueSize();
  buffer.insert(buffer.begin() + offset, name.begin(), name.end());
}

std::string EapMd5Challenge::getName() {
  int offset = VAL_OFFSET + getValueSize();
  int len = buffer.size() - offset;
  return std::string((const char *)&buffer[offset], len);
}

void EapPacket::setLength(unsigned short length) {
  std::array<byte, 2> bytes = radius::internal::short2NetworkBytes(length);
  buffer[2] = bytes[0];
  buffer[3] = bytes[1];
}

short EapPacket::getLength() {
  unsigned short l = radius::internal::networkBytes2Short(
      std::array<byte, 2>({{buffer[2], buffer[3]}}));
  return l;
}

void EapPacket::setData(const EapData &data) {
  buffer.insert(buffer.begin() + DATA_OFFSET, data.buffer.begin(),
                data.buffer.end());
}

EapData EapPacket::getData() {
  byte type = getType();
  if (type == SUCCESS || type == FAILURE) {
    throw PacketAccessException(
        "The EapPacket of this type doesn't have the data field");
  }

  std::vector<byte> tdBytes(buffer.begin() + DATA_OFFSET, buffer.end());
  return EapData(tdBytes);
}
