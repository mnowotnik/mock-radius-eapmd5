#include "packets/eap_packet.h"

void EapIdentity::setIdentity(const std::string &identity) {
    buffer.resize(buffer.size()+identity.size());
    std::copy(identity.begin(),identity.end(),buffer.begin()+DATA_OFFSET);
}

std::string EapIdentity::getIdentity() {
    return std::string((const char *)&(buffer[DATA_OFFSET]),
                       buffer.size() - DATA_OFFSET);
}

void EapMd5Challenge::setValue(const std::vector<byte> &value) {
    buffer.resize(VAL_OFFSET+value.size());
    std::copy(value.begin(),value.end(),buffer.begin()+VAL_OFFSET);
    setValueSize(value.size());
}

void EapMd5Challenge::setValue(const std::vector<byte> &value,const std::string &name) {
    buffer.resize(VAL_OFFSET+value.size()+name.size());
    std::copy(value.begin(),value.end(),buffer.begin()+VAL_OFFSET);
    std::copy(name.begin(),name.end(),buffer.begin()+value.size()+VAL_OFFSET);
    setValueSize(value.size());
}

std::vector<byte> EapMd5Challenge::getValue() {
    std::vector<byte>::iterator itEnd =
        buffer.begin() + VAL_OFFSET + getValueSize();
    return std::vector<byte>(buffer.begin() + VAL_OFFSET, itEnd);
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
    buffer.resize(buffer.size()+data.buffer.size());
    std::copy(data.buffer.begin(),data.buffer.end(),buffer.begin()+DATA_OFFSET);
    setLength(buffer.size());
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
