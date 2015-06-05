#include "packets/eap_packet.h"

using std::vector;
using std::string;
using std::array;

namespace radius {
namespace packets {

void EapIdentity::setIdentity(const string &identity) {
    buffer.resize(buffer.size() + identity.size());
    copy(identity.begin(), identity.end(), buffer.begin() + DATA_OFFSET);
}

string EapIdentity::getIdentity() {
    return string((const char *)&(buffer[DATA_OFFSET]),
                  buffer.size() - DATA_OFFSET);
}

void EapMd5Challenge::setValue(const vector<byte> &value) {
    buffer.resize(VAL_OFFSET + value.size());
    copy(value.begin(), value.end(), buffer.begin() + VAL_OFFSET);
    setValueSize(value.size());
}

void EapMd5Challenge::setValue(const vector<byte> &value, const string &name) {
    buffer.resize(VAL_OFFSET + value.size() + name.size());
    copy(value.begin(), value.end(), buffer.begin() + VAL_OFFSET);
    copy(name.begin(), name.end(), buffer.begin() + value.size() + VAL_OFFSET);
    setValueSize(value.size());
}

vector<byte> EapMd5Challenge::getValue() {
    vector<byte>::iterator itEnd = buffer.begin() + VAL_OFFSET + getValueSize();
    return vector<byte>(buffer.begin() + VAL_OFFSET, itEnd);
}

string EapMd5Challenge::getName() {
    int offset = VAL_OFFSET + getValueSize();
    int len = buffer.size() - offset;
    return string((const char *)&buffer[offset], len);
}

void EapPacket::setLength(unsigned short length) {
    array<byte, 2> bytes = short2NetworkBytes(length);
    buffer[2] = bytes[0];
    buffer[3] = bytes[1];
}

short EapPacket::getLength() {
    unsigned short l =
        networkBytes2Short(array<byte, 2>({{buffer[2], buffer[3]}}));
    return l;
}

void EapPacket::setData(const EapData &data) {
    buffer.resize(buffer.size() + data.buffer.size());
    copy(data.buffer.begin(), data.buffer.end(), buffer.begin() + DATA_OFFSET);
    setLength(buffer.size());
}

EapData EapPacket::getData() {
    byte type = getType();
    if (type == SUCCESS || type == FAILURE) {
        throw PacketAccessException(
            "The EapPacket of this type doesn't have the data field");
    }

    vector<byte> tdBytes(buffer.begin() + DATA_OFFSET, buffer.end());
    return EapData(tdBytes);
}
}
}
