#pragma once
#include <string>
#include <vector>
#include <array>
#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include "crypto.h"
#include "typedefs.h"
#include <random>
/* #include <climits> */
#include <algorithm>
#include <functional>

namespace radius {

bool checkAuthenticator(
    const packets::RadiusPacket &packet,
    const std::array<byte, 16> &authenticator = std::array<byte, 16>{});
bool checkMessageAuthenticator(
    const packets::RadiusPacket &packet, const std::string &secret,
    const std::array<byte, 16> &authenticator = std::array<byte, 16>{});

bool checkIntegrity(
    const packets::RadiusPacket &packet, const std::string &secret,
    const std::array<byte, 16> &authenticator = std::array<byte, 16>{});

bool isRequest(const packets::RadiusPacket &packet);
bool isValid(const packets::RadiusPacket &packet);

std::array<byte, 16>
calcAuthenticatorChecksum(const packets::RadiusPacket &packet,
                          const std::array<byte, 16> &authenticator);
std::array<byte, 16>
calcAuthenticatorChecksum(const packets::RadiusPacket &packet);

std::array<byte, 16>
calcMessageAuthenticatorChecksum(const packets::RadiusPacket &packet,
                                 const std::string &secret,
                                 const std::array<byte, 16> &authenticator);
std::array<byte, 16>
calcMessageAuthenticatorChecksum(const packets::RadiusPacket &packet);

void calcAndSetMsgAuth(packets::RadiusPacket &packet, const std::string &secret,
                       const std::array<byte, 16> &authenticator);
void calcAndSetMsgAuth(packets::RadiusPacket &packet,
                       const std::string &secret);
void calcAndSetAuth(packets::RadiusPacket &packet,
                    const std::array<byte, 16> &authenticator);
void calcAndSetAuth(packets::RadiusPacket &packet);

std::unique_ptr<packets::MessageAuthenticator>
findMessageAuthenticator(const packets::RadiusPacket &packet);

std::vector<byte> generateRandomBytes(unsigned int min, unsigned int max);
std::array<byte, 16> generateRandom16();
std::array<byte, 16> calcChalVal(const packets::EapPacket &packet,
                                 const std::string &secret);
packets::EapPacket makeIdentity(const std::string id);
}
