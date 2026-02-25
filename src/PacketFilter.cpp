#include "PacketFilter.h"

#include <ll/api/Config.h>
#include <ll/api/io/Logger.h>
#include <ll/api/io/LoggerRegistry.h>
#include <ll/api/memory/Hook.h>
#include <ll/api/mod/RegisterHelper.h>
#include <mc/deps/raknet/RakPeer.h>
#include <mc/deps/raknet/RakPeerInterface.h>
#include <mc/deps/raknet/Packet.h>
#include <mc/deps/raknet/RNS2RecvStruct.h>
#include <mc/deps/raknet/SystemAddress.h>
#include <mc/network/RakPeerHelper.h>
#include <mc/network/ConnectionDefinition.h>
#include <mc/network/ServerNetworkHandler.h>
#include <mc/network/NetworkIdentifier.h>
#include <mc/network/packet/PlayerAuthInputPacket.h>
#include <mc/network/packet/MovePlayerPacket.h>
#include <mc/world/phys/Vec3.h>

#include <cmath>
#include <filesystem>
#include <memory>

namespace packet_filter {

static Config                          config;
static std::shared_ptr<ll::io::Logger> log;

static ll::io::Logger& getLogger() {
    if (!log) log = ll::io::LoggerRegistry::getInstance().getOrCreate("PacketFilter");
    return *log;
}

Config& getConfig() { return config; }

bool loadConfig() {
    auto path = PacketFilter::getInstance().getSelf().getConfigDir() / "config.json";
    return ll::config::loadConfig(config, path);
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
    getLogger().info(
        "Loaded. filterEmptyPacket={}, fix0x86Crash={}, fixNaNCrash={}",
        config.filterEmptyPacket,
        config.fix0x86Crash,
        config.fixNaNCrash
    );
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

// 检测坐标是否合法（非 NaN、非 Inf、范围内）
static bool isValidPosition(float x, float y, float z) {
    if (std::isnan(x) || std::isnan(y) || std::isnan(z)) return false;
    if (std::isinf(x) || std::isinf(y) || std::isinf(z)) return false;
    constexpr float kMaxCoord = 3.0e7f; // MC 世界边界
    if (std::abs(x) > kMaxCoord || std::abs(z) > kMaxCoord) return false;
    if (y < -1000.0f || y > 1.0e6f) return false;
    return true;
}

// 原始数据报过滤
static bool handleIncomingDatagram(RakNet::RNS2RecvStruct* recv) {
    if (!config.enabled || !recv) return true;

    int bytesRead = recv->bytesRead;

    if (config.filterEmptyPacket && bytesRead <= 0) return false;

    if (bytesRead <= 0) return true;

    auto packetId = static_cast<unsigned char>(recv->data[0]);

    if (config.fix0x86Crash && packetId == 0x86 &&
        static_cast<size_t>(bytesRead) < sizeof(unsigned char) + sizeof(RakNet::SystemAddress)) {
        return false;
    }

    return true;
}

} // namespace packet_filter

// Hook peerStartup
LL_AUTO_TYPE_INSTANCE_HOOK(
    RakPeerHelperStartupHook,
    ll::memory::HookPriority::Normal,
    RakPeerHelper,
    &RakPeerHelper::peerStartup,
    ::RakNet::StartupResult,
    ::RakNet::RakPeerInterface* peer,
    ::ConnectionDefinition const& def,
    ::RakPeerHelper::PeerPurpose purpose
) {
    using namespace packet_filter;

    auto result = origin(peer, def, purpose);

    if (peer && config.enabled) {
        peer->SetIncomingDatagramEventHandler(handleIncomingDatagram);
        getLogger().info(
            "Datagram filter installed (filterEmptyPacket={}, fix0x86Crash={}, fixNaNCrash={})",
            config.filterEmptyPacket,
            config.fix0x86Crash,
            config.fixNaNCrash
        );
    }

    return result;
}

// Hook RakPeer::Receive
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

    if (config.filterEmptyPacket && packet->length == 0) {
        this->DeallocatePacket(packet);
        return nullptr;
    }

    return packet;
}

// Hook PlayerAuthInputPacket — 拦截 NaN 坐标崩服
LL_AUTO_TYPE_INSTANCE_HOOK(
    PlayerAuthInputPacketHook,
    ll::memory::HookPriority::Normal,
    ServerNetworkHandler,
    &ServerNetworkHandler::handle,
    void,
    ::NetworkIdentifier const& netId,
    ::PlayerAuthInputPacket const& packet
) {
    using namespace packet_filter;

    if (config.enabled && config.fixNaNCrash) {
        auto const& pos = packet.mPos;
        if (!isValidPosition(pos.x, pos.y, pos.z)) {
            getLogger().warn("Blocked PlayerAuthInputPacket with invalid position ({}, {}, {})", pos.x, pos.y, pos.z);
            return;
        }
    }

    origin(netId, packet);
}

// Hook MovePlayerPacket — 拦截 NaN 坐标崩服
LL_AUTO_TYPE_INSTANCE_HOOK(
    MovePlayerPacketHook,
    ll::memory::HookPriority::Normal,
    ServerNetworkHandler,
    &ServerNetworkHandler::handle,
    void,
    ::NetworkIdentifier const& netId,
    ::MovePlayerPacket const& packet
) {
    using namespace packet_filter;

    if (config.enabled && config.fixNaNCrash) {
        auto const& pos = packet.mPos;
        if (!isValidPosition(pos.x, pos.y, pos.z)) {
            getLogger().warn("Blocked MovePlayerPacket with invalid position ({}, {}, {})", pos.x, pos.y, pos.z);
            return;
        }
    }

    origin(netId, packet);
}

LL_REGISTER_MOD(packet_filter::PacketFilter, packet_filter::PacketFilter::getInstance());
