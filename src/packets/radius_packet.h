#ifndef RADIUS_PACKET_H_QMEYJOSQ
#define RADIUS_PACKET_H_QMEYJOSQ

#include "packets/common.h"
#include "packets/eap_packet.h"
#include "constants.h"
#include <map>
#include <vector>
#include <array>
#include <string>
#include <algorithm>
#include <memory>
#include <iostream>

namespace radius {
namespace packets {

const std::map<byte, std::string> RADIUS_ATTRIBUTE_TYPES = {
    {1, "User-Name"},
    {2, "User-Password"},
    {3, "CHAP-Password"},
    {4, "NAS-IP-Address"},
    {5, "NAS-Port"},
    {6, "Service-Type"},
    {7, "Framed-Protocol"},
    {8, "Framed-IP-Address"},
    {9, "Framed-IP-Netmask"},
    {10, "Framed-Routing"},
    {11, "Filter-Id"},
    {12, "Framed-MTU"},
    {13, "Framed-Compression"},
    {14, "Login-IP-Host"},
    {15, "Login-Service"},
    {16, "Login-TCP-Port"},
    {17, "(unassigned)"},
    {18, "Reply-Message"},
    {19, "Callback-Number"},
    {20, "Callback-Id"},
    {21, "(unassigned)"},
    {22, "Framed-Route"},
    {23, "Framed-IPX-Network"},
    {24, "State"},
    {25, "Class"},
    {26, "Vendor-Specific"},
    {27, "Session-Timeout"},
    {28, "Idle-Timeout"},
    {29, "Termination-Action"},
    {30, "Called-Station-Id"},
    {31, "Calling-Station-Id"},
    {32, "NAS-Identifier"},
    {33, "Proxy-State"},
    {34, "Login-LAT-Service"},
    {35, "Login-LAT-Node"},
    {36, "Login-LAT-Group"},
    {37, "Framed-AppleTalk-Link"},
    {38, "Framed-AppleTalk-Network"},
    {39, "Framed-AppleTalk-Zone"},
    {40, "Accounting"},
    {41, "Accounting"},
    {42, "Accounting"},
    {43, "Accounting"},
    {44, "Accounting"},
    {45, "Accounting"},
    {46, "Accounting"},
    {47, "Accounting"},
    {48, "Accounting"},
    {49, "Accounting"},
    {50, "Accounting"},
    {51, "Accounting"},
    {52, "Acct-Input-Gigawords"},
    {53, "Acct-Output-Gigawords"},
    {54, "Unused"},
    {55, "Event-Timestamp"},
    {56, "Unused"},
    {57, "Unused"},
    {58, "Unused"},
    {59, "Unused"},
    {60, "CHAP-Challenge"},
    {61, "NAS-Port-Type"},
    {62, "Port-Limit"},
    {63, "Login-LAT-Port"},
    {70, "ARAP-Password"},
    {71, "ARAP-Features"},
    {72, "ARAP-Zone-Access"},
    {73, "ARAP-Security"},
    {74, "ARAP-Security-Data"},
    {75, "Password-Retry"},
    {76, "Prompt"},
    {77, "Connect-Info"},
    {78, "Configuration-Token"},
    {79, "EAP-Message"},
    {80, "Message-Authenticator"},
    /* 81-83   (refer to [6]) */
    {84, "ARAP-Challenge-Response"},
    {85, "Acct-Interim-Interval"},
    /* 86      (refer to [7]) */
    {87, "NAS-Port-Id"},
    {88, "Framed-Pool"},
    {89, "Unused"}};

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
    static const byte USER_NAME = 1, USER_PASSWORD = 2, CHAP_PASSWORD = 3,
                      MESSAGE_AUTHENTICATOR = 80, EAP_MESSAGE = 79,
                      NAS_IP_ADDRESS = 4, NAS_IDENTIFIER = 32;
    static const byte MAX_TYPE_ID = 91;
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

    virtual void print(std::ostream &o) const {
        const auto &typeIt = RADIUS_ATTRIBUTE_TYPES.find((const byte)getType());
        if (typeIt == RADIUS_ATTRIBUTE_TYPES.end()) {
            o << "Unrecognized Attribute type";
        } else {
            o << typeIt->second;
        }
    }

    static RadiusAVP *factoryFun(const std::vector<byte> &bytes);

    friend std::ostream &operator<<(std::ostream &o, const RadiusAVP &b) {
        o << std::to_string((int)b.buffer.size()) + " ";
        b.print(o);
        return o;
    }
};

/**
 * type  : Any (<=63)
 * length : >=2
 * value : Any
 */
class RadiusAVPDefault : public RadiusAVP {

  protected:
    void validate() {
        if (getLength() < MIN_SIZE) {
            throw InvalidPacket("AVP length field value incorrect (<2)");
        }
    }

  public:
    RadiusAVPDefault(const std::vector<byte> &bytes) : RadiusAVP(bytes) {}
    RadiusAVPDefault() {
        buffer.resize(MIN_SIZE);
        setLength(buffer.size());
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
    const unsigned int MIN_LENGTH = 4;
    void validate();

  public:
    EapMessage(const std::vector<byte> &bytes) : RadiusAVP(bytes) {}
    EapMessage() {
        buffer.resize(MIN_LENGTH);
        setType(RadiusAVP::EAP_MESSAGE);
        setLength(buffer.size());
    }
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
    unsigned short getLength() const;

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


#endif /* end of include guard: RADIUS_PACKET_H_QMEYJOSQ */
