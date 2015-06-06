#include "radius_server.h"
#include <map>
#include <string>

using std::map;
using std::string;

const map<string, string> userPassMap = {{"John", "pass123"},
                                         {"Dorothy", "doro123"}};

const string secret = "secret";

namespace radius {

TEST_CASE("def") { RadiusServer server(userPassMap, secret); }
}
