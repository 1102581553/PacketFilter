# PacketFilter

适用于 [LeviLamina](https://github.com/LiteLDev/LeviLamina) 的网络数据包过滤插件，用于防御恶意构造的崩服数据包。

## 功能

- 修复 MCPE-228407 漏洞：拦截畸形 0x86 数据包导致的服务端 buffer over-read 崩溃
- 双层数据包过滤：在 RakNet 解析前（数据报层）和解析后（逻辑包层）分别拦截异常短包
- 可配置最小包长阈值，灵活适配不同服务端环境

## 安装

1. 安装 [LeviLamina](https://github.com/LiteLDev/LeviLamina) 1.9.5 或更高版本
2. 将插件放入 `plugins/` 目录
3. 启动服务端，插件会自动生成配置文件

## 配置

配置文件位于 `plugins/PacketFilter/config.json`：

```json
{
    "version": 1,
    "enabled": true,
    "minPacketSize": 2,
    "fix0x86Crash": true
}
