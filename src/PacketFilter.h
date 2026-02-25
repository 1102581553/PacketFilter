#pragma once
#include <ll/api/Config.h>
#include <ll/api/mod/NativeMod.h>

namespace packet_filter {

struct Config {
    int  version          = 1;
    bool enabled          = true;
    bool filterEmptyPacket = true;
    bool fix0x86Crash     = true;
};

Config& getConfig();
bool    loadConfig();
bool    saveConfig();

class PacketFilter {
public:
    static PacketFilter& getInstance();
    PacketFilter() : mSelf(*ll::mod::NativeMod::current()) {}
    [[nodiscard]] ll::mod::NativeMod& getSelf() const { return mSelf; }
    bool load();
    bool enable();
    bool disable();

private:
    ll::mod::NativeMod& mSelf;
};

} // namespace packet_filter
