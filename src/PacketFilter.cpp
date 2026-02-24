#include "PacketFilter.h"

#include <ll/api/Config.h>
#include <ll/api/io/Logger.h>
#include <ll/api/io/LoggerRegistry.h>
#include <ll/api/memory/Hook.h>
#include <ll/api/mod/RegisterHelper.h>
#include <mc/deps/raknet/RakPeer.h>
#include <mc/deps/raknet/Packet.h>

#include <filesystem>
#include <memory>

namespace packet_filter {

static Config config;
static std::shared_ptr<ll::io::Logger> log;

static ll::io::Logger& getLogger() {
    if (!log) log = ll::io::LoggerRegistry::getInstance().getOrCreate("PacketFilter");
    return *log;
}

Config& getConfig() { return config; }

bool loadConfig() {
    auto path = PacketFilter::getInstance().getSelf().getConfigDir() / "config.json";
    bool ok   = ll::config::loadConfig(config, path);
    if (config.minPacketSize < 1) config.minPacketSize = 2;
    return ok;
}

bool saveConfig() {
    auto path = PacketFilter::getInstance().getSelf().getConfigDir() / "config.json";
    return ll::config::saveConfig(config, path);
}

PacketFilter& PacketFilter::getInstance() {
    static PacketFilter instance;
    return instance;
}

bool PacketFilter::load() {
    std::filesystem::create_directories(getSelf().getConfigDir());
    if (!loadConfig()) {
        getLogger().warn("Failed to load config, using defaults");
        saveConfig();
    }
    getLogger().info("Loaded. minPacketSize={}", config.minPacketSize);
    return true;
}

bool PacketFilter::enable() {
    getLogger().info("Enabled");
    return true;
}

bool PacketFilter::disable() {
    getLogger().info("Disabled");
    return true;
}

} // namespace packet_filter

// ── Hook RakPeer::Receive，过滤过短的包 ───────────────────
LL_AUTO_TYPE_INSTANCE_HOOK(
    RakPeerReceiveHook,
    ll::memory::HookPriority::Normal,
    RakNet::RakPeer,
    &RakNet::RakPeer::$Receive,
    ::RakNet::Packet*
) {
    using namespace packet_filter;

    auto* packet = origin();
    if (!config.enabled || !packet) return packet;

    if (packet->length < config.minPacketSize) {
        this->DeallocatePacket(packet);
        return nullptr;
    }

    return packet;
}

LL_REGISTER_MOD(packet_filter::PacketFilter, packet_filter::PacketFilter::getInstance());
