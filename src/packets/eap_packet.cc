#include "packets/eap_packet.h"
#include <iostream>

using std::vector;
using std::string;
using std::array;

namespace radius {
namespace packets {

EapData *EapData::factoryFun(const std::vector<byte> &bytes) {

    if (bytes.size() < MIN_LENGTH) {
        throw InvalidPacket(
            "EapData::factoryFun. Invalid input buffer. Too small.");
    }
    byte type = bytes[0];

    EapData *ed;
    switch (type) {
    case IDENTITY:
        ed = new EapIdentity(bytes);
        break;
    case MD5_CHALLENGE:
        ed = new EapMd5Challenge(bytes);
        break;
    case NAK:
        ed = new EapNak(bytes);
        break;
    default:
        throw InvalidPacket("EapData::factoryFun. Unsupported type : " +
                            (int)type);
    }
    return ed;
}

void EapIdentity::setIdentity(const string &identity) {
    buffer.resize(buffer.size() + identity.size());
    copy(identity.begin(), identity.end(), buffer.begin() + DATA_OFFSET);
}

std::string EapIdentity::getIdentity() const {
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

short EapPacket::getLength() const {
    unsigned short l =
        networkBytes2Short(array<byte, 2>({{buffer[2], buffer[3]}}));
    return l;
}

void EapPacket::setData(const EapData &data) {
    buffer.resize(buffer.size() + data.buffer.size());
    copy(data.buffer.begin(), data.buffer.end(), buffer.begin() + DATA_OFFSET);
    setLength(buffer.size());
}

std::unique_ptr<EapData> EapPacket::getData() const {
    byte type = getType();
    if (type == SUCCESS || type == FAILURE) {
        throw PacketAccessException(
            "The EapPacket of this type doesn't have the data field");
    }

    vector<byte> tdBytes(buffer.begin() + DATA_OFFSET, buffer.end());
    return std::unique_ptr<EapData>(EapData::factoryFun(tdBytes));
}

std::ostream &operator<<(std::ostream &o, const EapPacket &packet) {

    const std::string ind1(4, ' ');
    o << "1 Type = " + std::to_string(packet.getType()) + '(' +
             packet.typeStr() + ')' + NL;
    o << "1 ID = " + std::to_string(packet.getIdentifier()) + NL;
    o << "2 Length = " + std::to_string(packet.getLength()) + NL;
    o << "Type-data:" << NL;
    o << ind1;

    if (packet.getType() == EapPacket::SUCCESS ||
        packet.getType() == EapPacket::FAILURE) {
        o << "None" << NL;
    } else {
        o << *(packet.getData());
        o << NL;
    }
    return o;
}
std::string EapPacket::typeStr() const {
    int type = getType();
    switch (type) {
    case REQUEST:
        return "Request";
    case RESPONSE:
        return "Response";
    case SUCCESS:
        return "Success";
    case FAILURE:
        return "Failure";
    default:
        return "UNRECOGNIZED EAP TYPE";
    }
}
}
}
