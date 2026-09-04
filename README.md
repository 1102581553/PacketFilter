# PacketFilter

A network packet filtering plugin for [LeviLamina](https://github.com/LiteLDev/LeviLamina), designed to defend against maliciously crafted crash packets.

## Features

- Fixes MCPE-228407: Intercepts malformed 0x86 packets that cause server-side buffer over-read crashes
- Dual-layer packet filtering: intercepts abnormally short packets both before RakNet parsing (datagram layer) and after parsing (logical packet layer)
- Configurable minimum packet size threshold, flexibly adaptable to different server environments

## Installation

1. Install [LeviLamina](https://github.com/LiteLDev/LeviLamina) 1.9.5 or later
2. Place the plugin into the `plugins/` directory
3. Start the server; the plugin will automatically generate the configuration file

## Configuration

The configuration file is located at `plugins/PacketFilter/config.json`:

```json
{
    "version": 1,
    "enabled": true,
    "minPacketSize": 2,
    "fix0x86Crash": true
}
```
