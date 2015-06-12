#pragma once
#include "packets/common.h"
#include "packets/eap_packet.h"
#include "constants.h"
#include <vector>
#include <array>
#include <string>
#include <memory>
#include <iostream>

namespace radius {
namespace packets {

class RadiusPacket;

/**
 * 0 : type
 * 1 : length
 * 2+ : value
 */
class RadiusAVP {
    friend RadiusPacket;

  public:
    // types
    static const byte MESSAGE_AUTHENTICATOR = 80, EAP_MESSAGE = 79,
                      NAS_IP_ADDRESS = 4, NAS_IDENTIFIER = 32;
    static const byte MIN_SIZE = 2;
    static const byte VAL_OFFSET = MIN_SIZE;

  protected:
    std::vector<byte> buffer;
    virtual void validate() = 0;

  public:
    RadiusAVP() : buffer(MIN_SIZE) {}
    RadiusAVP(const std::vector<byte> &bytes) : buffer(bytes) {}

    void setType(byte type) { buffer[0] = type; }
    byte getType() const { return buffer[0]; }

    void setLength(byte length) { buffer[1] = length; }
    byte getLength() const { return buffer[1]; }

    void setValue(const std::vector<byte> &value) {
        buffer.erase(buffer.begin() + VAL_OFFSET, buffer.end());
        buffer.insert(buffer.begin() + VAL_OFFSET, value.begin(), value.end());
        setLength(buffer.size());
    }
    std::vector<byte> getValue() const {
        std::vector<byte> value(buffer.begin() + VAL_OFFSET, buffer.end());
        return value;
    }

    std::vector<byte> getBuffer() const { return buffer; }

    virtual void print(std::ostream &o) const = 0;
    static RadiusAVP *factoryFun(const std::vector<byte> &bytes);

    friend std::ostream &operator<<(std::ostream &o, const RadiusAVP &b) {
        o << std::to_string((int)b.buffer.size()) + " ";
        b.print(o);
        return o;
    }
};

/**
 * type : 79
 * length : varying
 * value -> (part of EapPacket or whole) EapPacket:
 *      0 : type
 *      1 : identifier
 *      2-3 : length
 *      4+ : data -> (EPData)
 *          0 : protocol type
 *          1+ : type-data (if any)
 *
 * EapPacket can have >253 bytes so byte arrays have to be retrieved
 * and concatenated (or split) per instance
 */
class EapMessage : public RadiusAVP {
  protected:
    const int MIN_LENGTH = 4;
    void validate();

  public:
    EapMessage(const std::vector<byte> &bytes) : RadiusAVP(bytes) {}
    EapMessage() {
        buffer.resize(MIN_LENGTH);
        setType(RadiusAVP::EAP_MESSAGE);
        setLength(buffer.size());
    }
    void print(std::ostream &o) const { o << "Eap-Message"; }
};

/**
 * type : 80
 * length : 16
 * value : md5
 */
class MessageAuthenticator : public RadiusAVP {
    const byte LENGTH = 18;

  protected:
    void validate();

  public:
    MessageAuthenticator(const std::vector<byte> &bytes) : RadiusAVP(bytes) {}
    MessageAuthenticator();

    void setMd5(const std::array<byte, 16> &md5);
    std::array<byte, 16> getMd5();
    void print(std::ostream &o) const { o << "Message Authenticator"; }
};

/**
 * type : 4
 * length : 4
 * value : ipv4
 */
class NasIpAddr : public RadiusAVP {

    const byte LENGTH = 6;

  protected:
    void validate();

  public:
    NasIpAddr(const std::vector<byte> &bytes) : RadiusAVP(bytes) {}
    NasIpAddr() { setType(RadiusAVP::NAS_IP_ADDRESS); }

    void setIp(std::array<byte, 4> ip);

    void setIp(const std::string &ipStr);

    in_addr getIp();
    void print(std::ostream &o) const { o << "NAS-IP-Address"; }
};

/**
 * type  : 32
 * length : 3+
 * value : string
 */
class NasIdentifier : public RadiusAVP {

  protected:
    void validate();

  public:
    NasIdentifier(const std::vector<byte> &bytes) : RadiusAVP(bytes) {}
    NasIdentifier() { setType(NAS_IDENTIFIER); }

    void setIdentifier(const std::vector<byte> &id);
    void setIdentifier(const std::string &id);

    std::string getIdentifier();
    void print(std::ostream &o) const { o << "NAS Identifier"; }
};

/**
 * 0 : code
 * 1 : identifier
 * 2-3 : length
 * 4-20 : authenticator
 * 21+ : attribute-value list
 */
class RadiusPacket {
  private:
    const int MIN_LENGTH = 20;
    std::vector<byte> buffer;
    std::vector<byte>::iterator findAVP(const RadiusAVP &avp);
    void validate();

  public:
    // codes
    static const byte ACCESS_REQUEST = 1, ACCESS_ACCEPT = 2, ACCESS_REJECT = 3,
                      ACCESS_CHALLENGE = 11;
    static const int AVP_OFFSET = 20, AUTH_OFFSET = 4, AUTH_LEN = 16;

    RadiusPacket() : buffer(MIN_LENGTH) { setLength(MIN_LENGTH); }
    RadiusPacket(const std::vector<byte> &bytes);

    void setCode(byte code) { buffer[0] = code; }
    byte getCode() const { return buffer[0]; }

    void setIdentifier(byte identifier) { buffer[1] = identifier; }
    byte getIdentifier() const { return buffer[1]; }

    void setLength(unsigned short length);
    short getLength() const;

    void setAuthenticator(const std::array<byte, AUTH_LEN> &arr);
    std::array<byte, 16> getAuthenticator() const;

    std::vector<byte> getBuffer() const { return buffer; }

    /**
     * get buffer without avp list
     */
    std::vector<byte> getBufferWoAVP() const;

    bool replaceAVP(const RadiusAVP &oldAvp, const RadiusAVP &newAVP);
    bool removeAVP(const RadiusAVP &avp);
    void addAVP(const RadiusAVP &avp);
    std::vector<std::unique_ptr<RadiusAVP>> getAVPList() const;

    bool operator==(const RadiusPacket &rhs) { return rhs.buffer == buffer; }
    friend std::ostream &operator<<(std::ostream &o,
                                    const RadiusPacket &packet);
    std::string codeStr() const;
};
}
}
