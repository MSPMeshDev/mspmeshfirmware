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
#include <WebSocketsClient.h>

// WebSocket server configuration
#define PACKET_LOG_WS_HOST "meshdevapi.quirkydonkey.com"
#define PACKET_LOG_WS_PORT 443
#define PACKET_LOG_WS_PATH "/ws/device"

// Ring buffer sizes
#define PACKET_LOG_BUFFER_SIZE 64
#define LOG_BUFFER_SIZE 128
#define LOG_MESSAGE_MAX_LEN 256

// Reconnect timing
#define PACKET_LOG_INITIAL_RETRY_MS 1000
#define PACKET_LOG_MAX_RETRY_MS 60000

// WebSocket ping interval
#define PACKET_LOG_PING_INTERVAL_MS 30000

// Message types for wire protocol
enum PacketLogMessageType : uint8_t {
    PACKET_LOG_MSG_AUTH = 0x01,         // Device → Server: auth handshake
    PACKET_LOG_MSG_PACKET = 0x02,       // Device → Server: mesh packet
    PACKET_LOG_MSG_AUTH_OK = 0x03,      // Server → Device: auth confirmed
    PACKET_LOG_MSG_AUTH_FAIL = 0x04,    // Server → Device: auth rejected
    PACKET_LOG_MSG_LOG = 0x05,          // Device → Server: log record
    PACKET_LOG_MSG_ADMIN_CMD = 0x06,    // Server → Device: ToRadio protobuf command
    PACKET_LOG_MSG_ADMIN_OK = 0x07,     // Device → Server: FromRadio protobuf response
    PACKET_LOG_MSG_ADMIN_FAIL = 0x08,   // Device → Server: command failed
};

// Direction flag
enum PacketLogDirection : uint8_t {
    PACKET_LOG_DIR_INBOUND = 0x00,
    PACKET_LOG_DIR_OUTBOUND = 0x01,
};

/**
 * PacketLogger - sends mesh packets and logs to a remote server via WebSocket
 *
 * Wire protocol (binary WebSocket frames):
 * [1 byte type][1 byte direction][2 bytes length][payload]
 *
 * Message types (Device → Server):
 *   0x01 AUTH:       [32 bytes public_key][4 bytes node_id]
 *   0x02 PACKET:     [protobuf encoded MeshPacket]
 *   0x05 LOG:        [protobuf encoded LogRecord]
 *   0x07 ADMIN_OK:   [protobuf encoded FromRadio]
 *   0x08 ADMIN_FAIL: [error message string]
 *
 * Message types (Server → Device):
 *   0x03 AUTH_OK:    (no payload)
 *   0x04 AUTH_FAIL:  (no payload)
 *   0x06 ADMIN_CMD:  [protobuf encoded ToRadio]
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

    // Called from RedirectablePrint to forward logs
    void sendLog(meshtastic_LogRecord_Level level, const char *source, const char *message);

    bool isConnected() const { return wsConnected; }

  protected:
    virtual int32_t runOnce() override;

  private:
    WebSocketsClient webSocket;
    bool wsInitialized = false;
    bool wsConnected = false;
    bool authSent = false;
    bool authConfirmed = false;

    // Ring buffer for packets when disconnected
    struct BufferedPacket {
        meshtastic_MeshPacket packet;
        PacketLogDirection direction;
        bool valid;
    };
    BufferedPacket packetBuffer[PACKET_LOG_BUFFER_SIZE];
    uint8_t packetBufferHead = 0;
    uint8_t packetBufferCount = 0;

    // Ring buffer for logs when disconnected
    struct BufferedLog {
        meshtastic_LogRecord_Level level;
        char source[16];
        char message[LOG_MESSAGE_MAX_LEN];
        uint32_t time;
        bool valid;
    };
    BufferedLog logBuffer[LOG_BUFFER_SIZE];
    uint8_t logBufferHead = 0;
    uint8_t logBufferCount = 0;

    // WebSocket event handler
    void onWebSocketEvent(WStype_t type, uint8_t *payload, size_t length);

    // Internal methods
    void initWebSocket();
    void disconnect();
    bool sendAuthHandshake();
    bool sendPacketFrame(const meshtastic_MeshPacket *p, PacketLogDirection direction);
    bool sendLogFrame(const BufferedLog *log);
    void bufferPacket(const meshtastic_MeshPacket *p, PacketLogDirection direction);
    void bufferLog(meshtastic_LogRecord_Level level, const char *source, const char *message);
    void flushPacketBuffer();
    void flushLogBuffer();
    bool sendFrame(PacketLogMessageType type, PacketLogDirection direction, const uint8_t *payload, size_t len);

    // Admin command handling
    void handleAdminCommand(const uint8_t *payload, size_t len);
    bool sendAdminResponse(const uint8_t *fromRadioBuf, size_t len);
    bool sendAdminError(const char *errorMsg);
};

extern PacketLogger *packetLogger;

#endif // HAS_PACKET_LOGGER
