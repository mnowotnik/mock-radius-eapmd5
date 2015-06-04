#pragma once
#include "packets/common.h"
#include "typedefs.h"
#include <string>
#include <vector>

namespace{
    using std::vector;
}
namespace radius{
    namespace packets{
class EapMessage;
class EapPacket;

/**
 * EapPacket data field
 * 0 : type
 * 1+ : type-data
 */
class EapData {
    friend EapPacket;

  protected:
    const int MIN_LENGTH = 1;
    const int DATA_OFFSET = MIN_LENGTH;
    std::vector<byte> buffer;

  public:
    static const byte IDENTITY = 1, MD5_CHALLENGE = 4, NAK = 3;

    EapData(const std::vector<byte> &bytes) : buffer(bytes) {}
    EapData() : buffer(MIN_LENGTH) {}

    void setType(byte type) { buffer[0] = type; }

    byte getType() { return buffer[0]; }

    std::vector<byte> getBuffer() { return buffer; }
};

/**
 * type : 1
 * type-data : username/message
 */
class EapIdentity : public EapData {


  public:
    EapIdentity(const std::vector<byte> &bytes) : EapData(bytes) {}
    EapIdentity() { setType(EapData::IDENTITY); }

    void setIdentity(const std::string &identity);

    std::string getIdentity();
};

/**
 * type : 3
 * type-data :
 *      1 : desired authentication mechanism (EapData type)
 */
class EapNak : public EapData {

    const int LENGTH = 2;

  public:
    EapNak(const std::vector<byte> &bytes) : EapData(bytes) {}
    EapNak() {
        setType(EapData::NAK);
        buffer.reserve(LENGTH);
    }

    void setPrefAlgorithm(byte type) { buffer[1] = type; }

    byte getPrefAlgorithm() { return buffer[1]; }
};

/**
 * type : 4
 * type-data :
 *      1 : value-size
 *      + : value
 *      + : name
 */
class EapMd5Challenge : public EapData {

    const int VAL_OFFSET = DATA_OFFSET + 1;

  public:
    EapMd5Challenge(const std::vector<byte> &bytes) : EapData(bytes) {}
    EapMd5Challenge() { setType(EapData::MD5_CHALLENGE); }

    byte getValueSize() { return buffer[1]; }

    void setValueSize(byte size) { buffer[1] = size; }

    void setValue(const std::vector<byte> &value);
    void setValue(const std::vector<byte> &value, const std::string &name);

    std::vector<byte> getValue();

    std::string getName();
};

/**
 * 0 : type
 * 1 : identifier
 * 2-3 : length
 * 4+ : type-data
 */
class EapPacket {

    friend EapMessage;
    std::vector<byte> buffer;
    static const int MIN_LENGTH = 4;
    static const int DATA_OFFSET = MIN_LENGTH;

  public:
    static const byte REQUEST = 1, RESPONSE = 2, SUCCESS = 3, FAILURE = 4;

    EapPacket() : buffer(MIN_LENGTH) { setLength(MIN_LENGTH); }
    EapPacket(const std::vector<byte> &bytes) : buffer(bytes) {
        buffer.resize(getLength());
    }

    void setType(byte type) { buffer[0] = type; }
    byte getType() { return buffer[0]; }

    void setIdentifier(byte id) { buffer[1] = id; }
    byte getIdentifier() { return buffer[1]; }

    void setLength(unsigned short length);
    short getLength();

    void setData(const EapData &data);

    std::vector<byte> getBuffer() { return buffer; }

    EapData getData();
};
}
}
