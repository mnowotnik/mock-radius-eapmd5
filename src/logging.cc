#include "logging.h"

using radius::packets::RadiusPacket;

namespace radius {
namespace {

std::string byte2hex(const byte &byte) {
    char buf[5];
    sprintf(buf, "%02X ", byte);
    std::string out = buf;
    return out;
}
const int HEX_ROW_WIDTH = 10;
}

std::string packet2LogBytes(const std::vector<byte> &packet) {
    std::stringstream log;
    for (unsigned int i = 0; i < packet.size(); i++) {
        if (i % HEX_ROW_WIDTH == 0 && i > 0) {
            log << NL;
        }
        log << byte2hex(packet[i]);
    }
    return log.str();
}

void initLogger(const std::string &logPath, const std::string &logName) {
    try {
        std::vector<spdlog::sink_ptr> sinks;
        auto stdoutSink = std::make_shared<spdlog::sinks::stdout_sink_st>();
        stdoutSink->set_level(spdlog::level::info);
        sinks.push_back(stdoutSink);
        auto fileSink =
            std::make_shared<spdlog::sinks::simple_file_sink_mt>(logPath, true);
        fileSink->set_level(spdlog::level::debug);
        sinks.push_back(fileSink);
        auto combined_logger =
            std::make_shared<spdlog::logger>(logName, begin(sinks), end(sinks));
        spdlog::register_logger(combined_logger);
        spdlog::set_pattern("[%R] [%l] %v");
    } catch (const spdlog::spdlog_ex &ex) {
        std::cout << "initLogger failed: " << ex.what() << std::endl;
    }
}
}
