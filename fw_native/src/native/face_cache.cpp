#include "face_cache.h"

#include <cstring>
#include <mutex>
#include <unordered_map>
#include <utility>
#include <vector>

#include "../log.h"

namespace fw::native::face_cache {

namespace {

struct Entry {
    std::uint64_t hash = 0;
    void*         node = nullptr;
};

// Guarded even though everything here is main-thread-only: the teardown log
// and any future diagnostic reader are cheap to make safe, and a map being
// rehashed under a reader is an ugly way to find out otherwise.
std::mutex                                   g_mtx;
std::unordered_map<std::string, Entry>       g_masters;
std::unordered_map<std::string, std::string> g_recipes;

}  // namespace

void set_master(const std::string& key, std::uint64_t recipe_hash,
                void* master_node) {
    if (key.empty() || !master_node) return;
    std::lock_guard<std::mutex> lk(g_mtx);
    const auto it = g_masters.find(key);
    if (it != g_masters.end() && it->second.node != master_node) {
        // The previous master is deliberately left parked rather than freed —
        // see the note in the header. Say so, so a leak hunt has a starting
        // point instead of a mystery.
        FW_LOG("[face-cache] replacing master for '%s' (hash 0x%llX -> 0x%llX); "
               "the old node %p stays parked", key.c_str(),
               static_cast<unsigned long long>(it->second.hash),
               static_cast<unsigned long long>(recipe_hash), it->second.node);
    }
    g_masters[key] = Entry{recipe_hash, master_node};
    FW_LOG("[face-cache] master parked for '%s' hash=0x%llX node=%p (%zu "
           "cached)", key.c_str(),
           static_cast<unsigned long long>(recipe_hash), master_node,
           g_masters.size());
}

void* get_master(const std::string& key, std::uint64_t recipe_hash) noexcept {
    std::lock_guard<std::mutex> lk(g_mtx);
    const auto it = g_masters.find(key);
    if (it == g_masters.end()) return nullptr;
    if (it->second.hash != recipe_hash) {
        FW_LOG("[face-cache] miss for '%s': cached hash 0x%llX, wanted 0x%llX "
               "— the appearance changed, so the cached face is stale",
               key.c_str(),
               static_cast<unsigned long long>(it->second.hash),
               static_cast<unsigned long long>(recipe_hash));
        return nullptr;
    }
    return it->second.node;
}

void* peek_master(const std::string& key) noexcept {
    std::lock_guard<std::mutex> lk(g_mtx);
    const auto it = g_masters.find(key);
    return it == g_masters.end() ? nullptr : it->second.node;
}

void* any_master(char* peer_out, std::size_t peer_out_size) noexcept {
    std::lock_guard<std::mutex> lk(g_mtx);
    for (const auto& [key, e] : g_masters) {
        if (!e.node) continue;
        if (peer_out && peer_out_size) {
            const std::size_t n = key.size() < peer_out_size - 1
                                      ? key.size() : peer_out_size - 1;
            std::memcpy(peer_out, key.data(), n);
            peer_out[n] = 0;
        }
        return e.node;
    }
    if (peer_out && peer_out_size) peer_out[0] = 0;
    return nullptr;
}

void forget(const std::string& key) {
    std::lock_guard<std::mutex> lk(g_mtx);
    g_masters.erase(key);
}

void clear() {
    std::lock_guard<std::mutex> lk(g_mtx);
    if (!g_masters.empty() || !g_recipes.empty()) {
        FW_LOG("[face-cache] clearing %zu parked master(s) and %zu recipe(s)",
               g_masters.size(), g_recipes.size());
    }
    g_masters.clear();
    g_recipes.clear();
}

std::size_t size() noexcept {
    std::lock_guard<std::mutex> lk(g_mtx);
    return g_masters.size();
}

bool set_recipe(const std::string& peer_id, const std::string& recipe_line) {
    if (peer_id.empty()) return false;
    if (recipe_line.empty()) {
        // An empty line means DROP: the borrow uses it to discard a recipe
        // that will not parse, so it stops being retried every tick forever.
        std::lock_guard<std::mutex> lk(g_mtx);
        const bool had = g_recipes.erase(peer_id) > 0;
        g_masters.erase(peer_id);
        if (had) {
            FW_LOG("[face-cache] dropped the recipe for '%s'", peer_id.c_str());
        }
        return had;
    }
    std::lock_guard<std::mutex> lk(g_mtx);
    const auto it = g_recipes.find(peer_id);
    if (it != g_recipes.end() && it->second == recipe_line) return false;

    const bool had = (it != g_recipes.end());
    g_recipes[peer_id] = recipe_line;

    // A changed recipe makes any built master for this peer wrong. Drop it
    // here rather than relying on the hash check alone: that check is the
    // safety net, this is the intent.
    if (had) {
        const auto m = g_masters.find(peer_id);
        if (m != g_masters.end()) {
            FW_LOG("[face-cache] '%s' changed appearance — dropping the built "
                   "master %p so it gets rebuilt", peer_id.c_str(),
                   m->second.node);
            g_masters.erase(m);
        }
    }
    FW_LOG("[face-cache] recipe %s for '%s' (%zu bytes, %zu recipe(s) held)",
           had ? "UPDATED" : "stored", peer_id.c_str(), recipe_line.size(),
           g_recipes.size());
    return true;
}

std::string get_recipe(const std::string& peer_id) {
    std::lock_guard<std::mutex> lk(g_mtx);
    const auto it = g_recipes.find(peer_id);
    return it == g_recipes.end() ? std::string() : it->second;
}

std::vector<std::pair<std::string, std::string>> all_recipes() {
    std::lock_guard<std::mutex> lk(g_mtx);
    return {g_recipes.begin(), g_recipes.end()};
}

// FNV-1a. The requirement is only that it changes when the recipe changes;
// there is nothing adversarial about a locally-produced appearance string, so
// a cryptographic hash would buy nothing and cost a dependency.
std::uint64_t hash_recipe(const std::string& recipe_line) noexcept {
    std::uint64_t h = 1469598103934665603ull;
    for (const char c : recipe_line) {
        h ^= static_cast<std::uint8_t>(c);
        h *= 1099511628211ull;
    }
    return h;
}

}  // namespace fw::native::face_cache
