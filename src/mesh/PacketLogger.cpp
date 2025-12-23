#include "PacketLogger.h"

#if HAS_PACKET_LOGGER

#include "NodeDB.h"
#include "configuration.h"
#include "main.h"
#include "mesh-pb-constants.h"
#include <WiFi.h>
#include <WiFiClient.h>
#include <pb_encode.h>

// packetLogger is defined in main.cpp

PacketLogger::PacketLogger() : concurrency::OSThread("PacketLogger")
{
    // Initialize buffer
    for (int i = 0; i < PACKET_LOG_BUFFER_SIZE; i++) {
        buffer[i].valid = false;
    }
}

PacketLogger::~PacketLogger()
{
    stop();
}

void PacketLogger::start()
{
    LOG_INFO("PacketLogger: starting, server=%s:%u", PACKET_LOG_SERVER, PACKET_LOG_PORT);
    setIntervalFromNow(0);
}

void PacketLogger::stop()
{
    disconnect();
    LOG_INFO("PacketLogger: stopped");
}

void PacketLogger::onReceive(const meshtastic_MeshPacket *p)
{
    // Always buffer - never block the radio path
    bufferPacket(p, PACKET_LOG_DIR_INBOUND);
}

void PacketLogger::onSend(const meshtastic_MeshPacket *p)
{
    // Always buffer - never block the radio path
    bufferPacket(p, PACKET_LOG_DIR_OUTBOUND);
}

int32_t PacketLogger::runOnce()
{
    // Check if WiFi is connected first
    if (WiFi.status() != WL_CONNECTED) {
        LOG_DEBUG("PacketLogger: waiting for WiFi...");
        return 5000; // Check again in 5s
    }

    if (!connected) {
        uint32_t now = millis();
        if (now - lastReconnectAttempt >= reconnectDelay) {
            lastReconnectAttempt = now;
            LOG_DEBUG("PacketLogger: attempting connection to %s:%d", PACKET_LOG_SERVER, PACKET_LOG_PORT);

            if (connectToServer()) {
                LOG_INFO("PacketLogger: connected to server");
                reconnectDelay = PACKET_LOG_INITIAL_RETRY_MS;

                if (sendAuthHandshake()) {
                    LOG_INFO("PacketLogger: auth sent");
                } else {
                    LOG_WARN("PacketLogger: failed to send auth");
                    disconnect();
                }
            } else {
                // Exponential backoff
                reconnectDelay = min(reconnectDelay * 2, (uint32_t)PACKET_LOG_MAX_RETRY_MS);
                LOG_DEBUG("PacketLogger: connection failed, retry in %ums", reconnectDelay);
            }
        }
    }

    // Check if still connected
    if (connected && client) {
        WiFiClient *c = (WiFiClient *)client;
        if (!c->connected()) {
            LOG_WARN("PacketLogger: connection lost");
            disconnect();
        }
    }

    // Drain buffer when connected
    if (connected && bufferCount > 0) {
        flushBuffer();
    }

    // Run frequently when we have buffered packets, slower otherwise
    return (bufferCount > 0) ? 100 : 1000;
}

void PacketLogger::bufferPacket(const meshtastic_MeshPacket *p, PacketLogDirection direction)
{
    // Add to ring buffer, overwriting oldest if full
    buffer[bufferHead].packet = *p;
    buffer[bufferHead].direction = direction;
    buffer[bufferHead].valid = true;

    bufferHead = (bufferHead + 1) % PACKET_LOG_BUFFER_SIZE;
    if (bufferCount < PACKET_LOG_BUFFER_SIZE) {
        bufferCount++;
    }
}

void PacketLogger::flushBuffer()
{
    if (bufferCount == 0)
        return;

    LOG_DEBUG("PacketLogger: flushing %u buffered packets", bufferCount);

    // Find oldest packet in ring buffer
    uint8_t start = (bufferHead + PACKET_LOG_BUFFER_SIZE - bufferCount) % PACKET_LOG_BUFFER_SIZE;

    for (uint8_t i = 0; i < bufferCount; i++) {
        uint8_t idx = (start + i) % PACKET_LOG_BUFFER_SIZE;
        if (buffer[idx].valid) {
            if (!sendPacket(&buffer[idx].packet, buffer[idx].direction)) {
                // Send failed, stop flushing
                LOG_WARN("PacketLogger: send failed during flush");
                return;
            }
            buffer[idx].valid = false;
        }
    }

    bufferCount = 0;
}

bool PacketLogger::sendPacket(const meshtastic_MeshPacket *p, PacketLogDirection direction)
{
    uint8_t packetBuf[meshtastic_MeshPacket_size];
    size_t len = pb_encode_to_bytes(packetBuf, sizeof(packetBuf), &meshtastic_MeshPacket_msg, p);

    if (len == 0) {
        LOG_WARN("PacketLogger: failed to encode packet");
        return false;
    }

    return sendFrame(PACKET_LOG_MSG_PACKET, direction, packetBuf, len);
}

bool PacketLogger::connectToServer()
{
    if (client) {
        disconnect();
    }

    WiFiClient *c = new WiFiClient();

    // Set timeout
    c->setTimeout(10);

    LOG_DEBUG("PacketLogger: connecting to %s:%d", PACKET_LOG_SERVER, PACKET_LOG_PORT);

    if (!c->connect(PACKET_LOG_SERVER, PACKET_LOG_PORT)) {
        LOG_WARN("PacketLogger: failed to connect");
        delete c;
        return false;
    }

    client = c;
    connected = true;
    return true;
}

void PacketLogger::disconnect()
{
    if (client) {
        WiFiClient *c = (WiFiClient *)client;
        c->stop();
        delete c;
        client = nullptr;
    }
    connected = false;
}

bool PacketLogger::sendFrame(PacketLogMessageType type, PacketLogDirection direction, const uint8_t *payload, size_t len)
{
    if (!client || !connected)
        return false;

    WiFiClient *c = (WiFiClient *)client;

    // Frame format: [type:1][direction:1][length:2][payload:N]
    uint8_t header[4];
    header[0] = type;
    header[1] = direction;
    header[2] = (len >> 8) & 0xFF;
    header[3] = len & 0xFF;

    if (c->write(header, 4) != 4) {
        LOG_WARN("PacketLogger: failed to send header");
        disconnect();
        return false;
    }

    if (len > 0 && payload) {
        if (c->write(payload, len) != len) {
            LOG_WARN("PacketLogger: failed to send payload");
            disconnect();
            return false;
        }
    }

    return true;
}

bool PacketLogger::sendAuthHandshake()
{
    // Auth payload: [32 bytes public_key][4 bytes node_id]
    uint8_t authPayload[36];
    memset(authPayload, 0, sizeof(authPayload));

    // Copy public key
    if (owner.public_key.size == 32) {
        memcpy(authPayload, owner.public_key.bytes, 32);
    }

    // Copy node ID (4 bytes, big-endian)
    uint32_t nodeId = nodeDB->getNodeNum();
    authPayload[32] = (nodeId >> 24) & 0xFF;
    authPayload[33] = (nodeId >> 16) & 0xFF;
    authPayload[34] = (nodeId >> 8) & 0xFF;
    authPayload[35] = nodeId & 0xFF;

    return sendFrame(PACKET_LOG_MSG_AUTH, PACKET_LOG_DIR_INBOUND, authPayload, sizeof(authPayload));
}

#endif // HAS_PACKET_LOGGER
