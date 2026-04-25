#include "config.h"

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <string>

#include "log.h"

namespace fw::config {

namespace {

std::string trim(std::string s) {
    auto not_space = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

// Parse "peer_id=0xHEX" into (peer_id, formid). Returns false on malformed.
bool parse_ghost_map(const std::string& raw,
                     std::string* peer_id_out,
                     std::uint32_t* form_id_out)
{
    const auto eq = raw.find('=');
    if (eq == std::string::npos) return false;
    const std::string left  = trim(raw.substr(0, eq));
    const std::string right = trim(raw.substr(eq + 1));
    if (left.empty() || right.empty()) return false;

    try {
        const auto radix = (right.size() >= 2 && right[0] == '0' &&
                            (right[1] == 'x' || right[1] == 'X')) ? 16 : 10;
        std::size_t consumed = 0;
        const unsigned long v = std::stoul(right, &consumed, radix);
        if (consumed == 0) return false;
        if (peer_id_out) *peer_id_out = left;
        if (form_id_out) *form_id_out = static_cast<std::uint32_t>(v);
        return true;
    } catch (...) {
        return false;
    }
}

// "127.0.0.1:31337" → (host, port). Returns false if port missing.
bool parse_endpoint(const std::string& raw,
                    std::string* host_out, std::uint16_t* port_out)
{
    const auto colon = raw.rfind(':');
    if (colon == std::string::npos) return false;
    const std::string host = trim(raw.substr(0, colon));
    const std::string port = trim(raw.substr(colon + 1));
    if (host.empty() || port.empty()) return false;
    try {
        const unsigned long p = std::stoul(port);
        if (p == 0 || p > 65535) return false;
        if (host_out) *host_out = host;
        if (port_out) *port_out = static_cast<std::uint16_t>(p);
        return true;
    } catch (...) {
        return false;
    }
}

} // namespace

Settings load(const std::filesystem::path& path) {
    Settings s{};
    s.source_path = path;

    std::ifstream f(path);
    if (!f.is_open()) {
        FW_WRN("config: %s not found — using built-in defaults", path.string().c_str());
        return s;
    }

    std::string line;
    int line_no = 0;
    while (std::getline(f, line)) {
        ++line_no;
        line = trim(line);
        if (line.empty()) continue;
        if (line[0] == '#' || line[0] == ';') continue;

        const auto eq = line.find('=');
        if (eq == std::string::npos) {
            FW_WRN("config: %s:%d malformed (no '='): %s",
                   path.string().c_str(), line_no, line.c_str());
            continue;
        }
        const std::string key = trim(line.substr(0, eq));
        const std::string value = trim(line.substr(eq + 1));

        if (key == "server") {
            std::string h; std::uint16_t p = 0;
            if (parse_endpoint(value, &h, &p)) {
                s.server_host = h;
                s.server_port = p;
            } else {
                FW_WRN("config: bad 'server' value: %s", value.c_str());
            }
        } else if (key == "client_id") {
            s.client_id = value;
        } else if (key == "ghost_map") {
            std::string peer; std::uint32_t fid = 0;
            if (parse_ghost_map(value, &peer, &fid)) {
                s.ghost_map_peer_id = peer;
                s.ghost_map_form_id = fid;
            } else {
                FW_WRN("config: bad 'ghost_map' value: %s", value.c_str());
            }
        } else if (key == "log_level") {
            s.log_level = value;
        } else if (key == "auto_continue") {
            // Accept 1/0/true/false/yes/no.
            const auto& v = value;
            if (v == "1" || v == "true" || v == "yes" || v == "on" ||
                v == "TRUE" || v == "YES" || v == "ON") {
                s.auto_continue = true;
            } else if (v == "0" || v == "false" || v == "no" || v == "off" ||
                       v == "FALSE" || v == "NO" || v == "OFF") {
                s.auto_continue = false;
            } else {
                FW_WRN("config: bad 'auto_continue' value: %s", v.c_str());
            }
        } else if (key == "auto_continue_delay_ms") {
            try {
                const unsigned long ms = std::stoul(value);
                s.auto_continue_delay_ms = static_cast<std::uint32_t>(ms);
            } catch (...) {
                FW_WRN("config: bad 'auto_continue_delay_ms' value: %s", value.c_str());
            }
        } else if (key == "auto_load_save") {
            s.auto_load_save = value;
        } else {
            FW_WRN("config: %s:%d unknown key '%s' — ignoring",
                   path.string().c_str(), line_no, key.c_str());
        }
    }

    FW_LOG("config: loaded from %s  server=%s:%u  client_id=%s  ghost=%s->0x%X  log=%s  auto_load_save=%s",
           path.string().c_str(),
           s.server_host.c_str(), s.server_port,
           s.client_id.c_str(),
           s.ghost_map_peer_id.empty() ? "(none)" : s.ghost_map_peer_id.c_str(),
           s.ghost_map_form_id,
           s.log_level.c_str(),
           s.auto_load_save.empty() ? "(disabled)" : s.auto_load_save.c_str());
    return s;
}

} // namespace fw::config
