#pragma once
#include <mc/deps/raknet/PluginInterface2.h>
#include <mc/deps/raknet/PluginReceiveResult.h>
#include <mc/deps/raknet/Packet.h>
#include <cstring>

namespace packet_filter {

// RakNet::Packet 中 length 字段偏移
static constexpr size_t kPacketLengthOffset = 152;

// RakNet::RNS2RecvStruct 布局偏移
static constexpr size_t kRecvDataOffset      = 0;     // char data[1600]
static constexpr size_t kRecvBytesReadOffset  = 1600;  // int bytes_read

class PacketFilterPlugin : public RakNet::PluginInterface2 {
public:
    explicit PacketFilterPlugin(uint minSize) : mMinSize(minSize) {}

    ::RakNet::PluginReceiveResult OnReceive(::RakNet::Packet* packet) override {
        if (!packet) return ::RakNet::PluginReceiveResult::StopProcessingAndDeallocate;
        uint len = 0;
        std::memcpy(&len, reinterpret_cast<char*>(packet) + kPacketLengthOffset, sizeof(uint));
        if (len < mMinSize) return ::RakNet::PluginReceiveResult::StopProcessingAndDeallocate;
        return ::RakNet::PluginReceiveResult::ContinueProcessing;
    }

    void setMinSize(uint s) { mMinSize = s; }
private:
    uint mMinSize;
};

} // namespace packet_filter
