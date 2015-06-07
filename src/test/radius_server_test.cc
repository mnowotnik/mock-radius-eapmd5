#include "radius_server.h"
#include "spdlog/spdlog.h"
#include "catch.hpp"
#include <map>
#include <string>

using std::map;
using std::string;

const map<string, string> userPassMap = {{"John", "pass123"},
                                         {"Dorothy", "doro123"}};

const string secret = "secret";
/* auto null_sink = make_shared<spdlog::sinks::null_sink_st> (); */

namespace radius {

TEST_CASE("RadiusServer test") {

    auto console = spdlog::stdout_logger_mt("console");
    console->info("Log");
    /* auto logger = make_shared<spdlog::logger>("null_logger", null_sink); */
    RadiusServer server(userPassMap, secret, console);
}
}
