// peer_names — implementation. The why is in peer_names.h.

#include "peer_names.h"

#include <mutex>
#include <unordered_map>

namespace fw::net::peer_names {

namespace {

std::mutex g_mtx;
std::unordered_map<std::string, std::string> g_names;   // peer_id -> name
std::string g_self_id;
std::string g_self_name;

}  // namespace

void set_self(const std::string& peer_id, const std::string& display_name) {
    // The server keeps only printable ASCII, cut at 15 and trimmed
    // (sanitize_display_name). The same rule here, so our own name reads the
    // same on our screen as on everyone else's.
    std::string clean;
    for (const char c : display_name) {
        if (c >= 0x20 && c < 0x7F) clean.push_back(c);
    }
    if (clean.size() > 15) clean.resize(15);
    const auto first = clean.find_first_not_of(' ');
    clean = (first == std::string::npos)
        ? std::string()
        : clean.substr(first, clean.find_last_not_of(' ') - first + 1);

    std::lock_guard lk(g_mtx);
    g_self_id   = peer_id;
    g_self_name = clean;
}

void on_join(const std::string& peer_id, const std::string& display_name) {
    if (peer_id.empty()) return;
    std::lock_guard lk(g_mtx);
    g_names[peer_id] = display_name;
}

void on_leave(const std::string& peer_id) {
    std::lock_guard lk(g_mtx);
    g_names.erase(peer_id);
}

std::string display(const std::string& peer_id) {
    std::lock_guard lk(g_mtx);
    if (!g_self_id.empty() && peer_id == g_self_id) {
        return g_self_name.empty() ? peer_id : g_self_name;
    }
    const auto it = g_names.find(peer_id);
    if (it == g_names.end() || it->second.empty()) return peer_id;
    return it->second;
}

}  // namespace fw::net::peer_names
