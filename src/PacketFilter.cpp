#include "PacketFilter.h"
#include "PacketFilterPlugin.h"

#include <ll/api/Config.h>
#include <ll/api/io/Logger.h>
#include <ll/api/io/LoggerRegistry.h>
#include <ll/api/memory/Hook.h>
#include <ll/api/mod/RegisterHelper.h>
#include <mc/deps/raknet/RakPeer.h>
#include <mc/deps/raknet/SocketDescriptor.h>
#include <mc/deps/raknet/StartupResult.h>

#include <filesystem>
#include <memory>

namespace packet_filter {

static Config config;
static std::shared_ptr<ll::io::Logger> log;
static std::unique_ptr<PacketFilterPlugin> gPlugin;

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
    gPlugin = std::make_unique<PacketFilterPlugin>(config.minPacketSize);
    getLogger().info("Loaded. minPacketSize={}", config.minPacketSize);
    return true;
}

bool PacketFilter::enable() {
    if (gPlugin) gPlugin->setMinSize(config.minPacketSize);
    getLogger().info("Enabled");
    return true;
}

bool PacketFilter::disable() {
    getLogger().info("Disabled");
    return true;
}

} // namespace packet_filter

// ── Hook RakPeer::Startup，attach 插件 ────────────────────
LL_AUTO_TYPE_INSTANCE_HOOK(
    RakPeerStartupHook,
    ll::memory::HookPriority::Normal,
    RakNet::RakPeer,
    &RakNet::RakPeer::$Startup,
    ::RakNet::StartupResult,
    uint maxConnections,
    ::RakNet::SocketDescriptor* socketDescriptors,
    uint socketDescriptorCount,
    int threadPriority
) {
    auto result = origin(maxConnections, socketDescriptors, socketDescriptorCount, threadPriority);
    if (result == ::RakNet::StartupResult::Started && packet_filter::gPlugin) {
        this->AttachPlugin(packet_filter::gPlugin.get());
    }
    return result;
}

LL_REGISTER_MOD(packet_filter::PacketFilter, packet_filter::PacketFilter::getInstance());
