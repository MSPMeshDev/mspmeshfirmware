#pragma once

#include "configuration.h"

// Enable for ESP32 with WiFi
#if HAS_WIFI && defined(ARCH_ESP32)
#define HAS_PACKET_LOGGER 1
#endif

#if HAS_PACKET_LOGGER

#include "MeshTypes.h"
#include "concurrency/OSThread.h"
#include "mesh-pb-constants.h"

// Hardcoded server for testing
#define PACKET_LOG_SERVER "192.168.3.250"
#define PACKET_LOG_PORT 8257

// Ring buffer size for packets when disconnected
#define PACKET_LOG_BUFFER_SIZE 64

// Reconnect timing
#define PACKET_LOG_INITIAL_RETRY_MS 1000
#define PACKET_LOG_MAX_RETRY_MS 60000

// Message types for wire protocol
enum PacketLogMessageType : uint8_t {
    PACKET_LOG_MSG_AUTH = 0x01,
    PACKET_LOG_MSG_PACKET = 0x02,
    PACKET_LOG_MSG_AUTH_OK = 0x03,
    PACKET_LOG_MSG_AUTH_FAIL = 0x04,
    PACKET_LOG_MSG_SYSLOG = 0x05,
};

// Direction flag
enum PacketLogDirection : uint8_t {
    PACKET_LOG_DIR_INBOUND = 0x00,
    PACKET_LOG_DIR_OUTBOUND = 0x01,
};

/**
 * PacketLogger - sends all mesh packets to a remote logging server
 *
 * Wire protocol (simple framed messages):
 * [1 byte type][1 byte direction][2 bytes length][payload]
 *
 * Auth message payload: [32 bytes public_key][4 bytes node_id]
 * Packet message payload: [protobuf encoded MeshPacket]
 */
class PacketLogger : public concurrency::OSThread
{
  public:
    PacketLogger();
    virtual ~PacketLogger();

    void start();
    void stop();

    // Called for every inbound packet
    void onReceive(const meshtastic_MeshPacket *p);

    // Called for every outbound packet
    void onSend(const meshtastic_MeshPacket *p);

    bool isConnected() const { return connected; }

  protected:
    virtual int32_t runOnce() override;

  private:
    bool connected = false;
    void *client = nullptr;  // WiFiClient*

    // Reconnect backoff
    uint32_t reconnectDelay = PACKET_LOG_INITIAL_RETRY_MS;
    uint32_t lastReconnectAttempt = 0;

    // Ring buffer for packets when disconnected
    struct BufferedPacket {
        meshtastic_MeshPacket packet;
        PacketLogDirection direction;
        bool valid;
    };
    BufferedPacket buffer[PACKET_LOG_BUFFER_SIZE];
    uint8_t bufferHead = 0;
    uint8_t bufferCount = 0;

    // Internal methods
    bool connectToServer();
    void disconnect();
    bool sendAuthHandshake();
    bool sendPacket(const meshtastic_MeshPacket *p, PacketLogDirection direction);
    void bufferPacket(const meshtastic_MeshPacket *p, PacketLogDirection direction);
    void flushBuffer();
    bool sendFrame(PacketLogMessageType type, PacketLogDirection direction, const uint8_t *payload, size_t len);
};

extern PacketLogger *packetLogger;

#endif // HAS_PACKET_LOGGER
