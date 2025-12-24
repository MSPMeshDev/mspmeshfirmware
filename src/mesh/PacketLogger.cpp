#include "PacketLogger.h"

#if HAS_PACKET_LOGGER

#include "MeshService.h"
#include "NodeDB.h"
#include "PhoneAPI.h"
#include "RTC.h"
#include "TypeConversions.h"
#include "configuration.h"
#include "main.h"
#include "mesh-pb-constants.h"
#include <WiFi.h>
#include <pb_decode.h>
#include <pb_encode.h>

PacketLogger::PacketLogger() : concurrency::OSThread("PacketLogger")
{
    // Initialize packet buffer
    for (int i = 0; i < PACKET_LOG_BUFFER_SIZE; i++) {
        packetBuffer[i].valid = false;
    }
    // Initialize log buffer
    for (int i = 0; i < LOG_BUFFER_SIZE; i++) {
        logBuffer[i].valid = false;
    }
    wsInitialized = false;
}

PacketLogger::~PacketLogger()
{
    stop();
}

void PacketLogger::start()
{
    LOG_INFO("PacketLogger: starting, server=wss://%s:%u%s", PACKET_LOG_WS_HOST, PACKET_LOG_WS_PORT, PACKET_LOG_WS_PATH);
    setIntervalFromNow(0);
}

void PacketLogger::stop()
{
    disconnect();
    LOG_INFO("PacketLogger: stopped");
}

void PacketLogger::onReceive(const meshtastic_MeshPacket *p)
{
    bufferPacket(p, PACKET_LOG_DIR_INBOUND);
}

void PacketLogger::onSend(const meshtastic_MeshPacket *p)
{
    bufferPacket(p, PACKET_LOG_DIR_OUTBOUND);
}

void PacketLogger::sendLog(meshtastic_LogRecord_Level level, const char *source, const char *message)
{
    bufferLog(level, source, message);
}

int32_t PacketLogger::runOnce()
{
    // Check WiFi first
    if (WiFi.status() != WL_CONNECTED) {
        if (wsConnected) {
            LOG_DEBUG("PacketLogger: WiFi lost, disconnecting WebSocket");
            disconnect();
        }
        wsInitialized = false; // Reset so we reinitialize when WiFi returns
        return 5000; // Check again in 5s
    }

    // Initialize WebSocket connection once when WiFi is available
    if (!wsInitialized) {
        initWebSocket();
        wsInitialized = true;
    }

    // Service WebSocket - this handles ping/pong, reconnects, etc.
    webSocket.loop();

    // Connected - flush buffers if auth confirmed
    if (wsConnected && authConfirmed) {
        if (packetBufferCount > 0) {
            flushPacketBuffer();
        }
        if (logBufferCount > 0) {
            flushLogBuffer();
        }
    }

    // Run more frequently when we have buffered data or not connected
    return (packetBufferCount > 0 || logBufferCount > 0 || !wsConnected) ? 100 : 500;
}

void PacketLogger::initWebSocket()
{
    LOG_INFO("PacketLogger: initializing WebSocket to wss://%s:%d%s", PACKET_LOG_WS_HOST, PACKET_LOG_WS_PORT, PACKET_LOG_WS_PATH);

    // Setup WebSocket event handler using lambda
    webSocket.onEvent([this](WStype_t type, uint8_t *payload, size_t length) {
        this->onWebSocketEvent(type, payload, length);
    });

    // Connect with TLS (no fingerprint = insecure mode, accepts any cert)
    // TODO: For production, add proper CA certificate validation using beginSslWithCA()
    webSocket.beginSSL(PACKET_LOG_WS_HOST, PACKET_LOG_WS_PORT, PACKET_LOG_WS_PATH);

    // Set reconnect interval - library handles automatic reconnection
    webSocket.setReconnectInterval(PACKET_LOG_INITIAL_RETRY_MS);

    // Enable ping/pong for keepalive
    webSocket.enableHeartbeat(PACKET_LOG_PING_INTERVAL_MS, 10000, 2);
}

void PacketLogger::disconnect()
{
    webSocket.disconnect();
    wsConnected = false;
    authSent = false;
    authConfirmed = false;
}

void PacketLogger::onWebSocketEvent(WStype_t type, uint8_t *payload, size_t length)
{
    switch (type) {
    case WStype_DISCONNECTED:
        LOG_WARN("PacketLogger: WebSocket disconnected");
        wsConnected = false;
        authSent = false;
        authConfirmed = false;
        break;

    case WStype_CONNECTED:
        LOG_INFO("PacketLogger: WebSocket connected to %s", payload);
        wsConnected = true;

        // Send auth handshake immediately
        if (sendAuthHandshake()) {
            LOG_INFO("PacketLogger: auth handshake sent");
            authSent = true;
        } else {
            LOG_WARN("PacketLogger: failed to send auth handshake");
            disconnect();
        }
        break;

    case WStype_BIN:
        // Handle incoming binary messages from server
        // Frame format: [type:1][direction:1][length:2][payload:N]
        if (length >= 4) {
            PacketLogMessageType msgType = (PacketLogMessageType)payload[0];
            // payload[1] is direction (unused for server→device)
            uint16_t payloadLen = (payload[2] << 8) | payload[3];

            switch (msgType) {
            case PACKET_LOG_MSG_AUTH_OK:
                LOG_INFO("PacketLogger: auth confirmed by server");
                authConfirmed = true;
                break;
            case PACKET_LOG_MSG_AUTH_FAIL:
                LOG_WARN("PacketLogger: auth rejected by server");
                disconnect();
                break;
            case PACKET_LOG_MSG_ADMIN_CMD:
                if (length >= 4 + payloadLen && authConfirmed) {
                    LOG_INFO("PacketLogger: received admin command (%u bytes)", payloadLen);
                    handleAdminCommand(payload + 4, payloadLen);
                } else if (!authConfirmed) {
                    LOG_WARN("PacketLogger: admin command rejected - not authenticated");
                    sendAdminError("Not authenticated");
                }
                break;
            default:
                LOG_DEBUG("PacketLogger: received message type 0x%02x", msgType);
                break;
            }
        } else if (length >= 1) {
            // Handle legacy short frames (just type byte for AUTH_OK/AUTH_FAIL)
            PacketLogMessageType msgType = (PacketLogMessageType)payload[0];
            if (msgType == PACKET_LOG_MSG_AUTH_OK) {
                LOG_INFO("PacketLogger: auth confirmed by server");
                authConfirmed = true;
            } else if (msgType == PACKET_LOG_MSG_AUTH_FAIL) {
                LOG_WARN("PacketLogger: auth rejected by server");
                disconnect();
            }
        }
        break;

    case WStype_TEXT:
        // We don't expect text messages, but log them
        LOG_DEBUG("PacketLogger: received text: %s", payload);
        break;

    case WStype_PING:
        LOG_DEBUG("PacketLogger: ping");
        break;

    case WStype_PONG:
        LOG_DEBUG("PacketLogger: pong");
        break;

    case WStype_ERROR:
        LOG_ERROR("PacketLogger: WebSocket error");
        break;

    default:
        break;
    }
}

void PacketLogger::bufferPacket(const meshtastic_MeshPacket *p, PacketLogDirection direction)
{
    // Add to ring buffer, overwriting oldest if full
    packetBuffer[packetBufferHead].packet = *p;
    packetBuffer[packetBufferHead].direction = direction;
    packetBuffer[packetBufferHead].valid = true;

    packetBufferHead = (packetBufferHead + 1) % PACKET_LOG_BUFFER_SIZE;
    if (packetBufferCount < PACKET_LOG_BUFFER_SIZE) {
        packetBufferCount++;
    }
}

void PacketLogger::bufferLog(meshtastic_LogRecord_Level level, const char *source, const char *message)
{
    BufferedLog *log = &logBuffer[logBufferHead];
    log->level = level;
    log->time = getValidTime(RTCQuality::RTCQualityDevice, false);

    // Safe string copy
    if (source) {
        strncpy(log->source, source, sizeof(log->source) - 1);
        log->source[sizeof(log->source) - 1] = '\0';
    } else {
        log->source[0] = '\0';
    }

    if (message) {
        strncpy(log->message, message, sizeof(log->message) - 1);
        log->message[sizeof(log->message) - 1] = '\0';
    } else {
        log->message[0] = '\0';
    }

    log->valid = true;

    logBufferHead = (logBufferHead + 1) % LOG_BUFFER_SIZE;
    if (logBufferCount < LOG_BUFFER_SIZE) {
        logBufferCount++;
    }
}

void PacketLogger::flushPacketBuffer()
{
    if (packetBufferCount == 0 || !wsConnected || !authConfirmed)
        return;

    // Find oldest packet in ring buffer
    uint8_t start = (packetBufferHead + PACKET_LOG_BUFFER_SIZE - packetBufferCount) % PACKET_LOG_BUFFER_SIZE;
    uint8_t flushed = 0;

    for (uint8_t i = 0; i < packetBufferCount && flushed < 10; i++) { // Limit per cycle to avoid blocking
        uint8_t idx = (start + i) % PACKET_LOG_BUFFER_SIZE;
        if (packetBuffer[idx].valid) {
            if (!sendPacketFrame(&packetBuffer[idx].packet, packetBuffer[idx].direction)) {
                LOG_WARN("PacketLogger: packet send failed during flush");
                return;
            }
            packetBuffer[idx].valid = false;
            flushed++;
        }
    }

    // Update count
    packetBufferCount -= flushed;
    if (flushed > 0) {
        LOG_DEBUG("PacketLogger: flushed %u packets, %u remaining", flushed, packetBufferCount);
    }
}

void PacketLogger::flushLogBuffer()
{
    if (logBufferCount == 0 || !wsConnected || !authConfirmed)
        return;

    // Find oldest log in ring buffer
    uint8_t start = (logBufferHead + LOG_BUFFER_SIZE - logBufferCount) % LOG_BUFFER_SIZE;
    uint8_t flushed = 0;

    for (uint8_t i = 0; i < logBufferCount && flushed < 20; i++) { // Limit per cycle
        uint8_t idx = (start + i) % LOG_BUFFER_SIZE;
        if (logBuffer[idx].valid) {
            if (!sendLogFrame(&logBuffer[idx])) {
                LOG_WARN("PacketLogger: log send failed during flush");
                return;
            }
            logBuffer[idx].valid = false;
            flushed++;
        }
    }

    // Update count
    logBufferCount -= flushed;
}

bool PacketLogger::sendPacketFrame(const meshtastic_MeshPacket *p, PacketLogDirection direction)
{
    uint8_t packetBuf[meshtastic_MeshPacket_size];
    size_t len = pb_encode_to_bytes(packetBuf, sizeof(packetBuf), &meshtastic_MeshPacket_msg, p);

    if (len == 0) {
        LOG_WARN("PacketLogger: failed to encode packet");
        return false;
    }

    return sendFrame(PACKET_LOG_MSG_PACKET, direction, packetBuf, len);
}

bool PacketLogger::sendLogFrame(const BufferedLog *log)
{
    // Encode as protobuf LogRecord
    meshtastic_LogRecord logRecord = meshtastic_LogRecord_init_zero;
    logRecord.level = log->level;
    logRecord.time = log->time;
    strncpy(logRecord.source, log->source, sizeof(logRecord.source) - 1);
    strncpy(logRecord.message, log->message, sizeof(logRecord.message) - 1);

    uint8_t logBuf[meshtastic_LogRecord_size];
    size_t len = pb_encode_to_bytes(logBuf, sizeof(logBuf), meshtastic_LogRecord_fields, &logRecord);

    if (len == 0) {
        LOG_WARN("PacketLogger: failed to encode log");
        return false;
    }

    return sendFrame(PACKET_LOG_MSG_LOG, PACKET_LOG_DIR_OUTBOUND, logBuf, len);
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

bool PacketLogger::sendFrame(PacketLogMessageType type, PacketLogDirection direction, const uint8_t *payload, size_t len)
{
    if (!wsConnected)
        return false;

    // Max frame size: 4 byte header + max payload (LogRecord or MeshPacket)
    // meshtastic_MeshPacket_size is ~300 bytes, meshtastic_LogRecord_size is ~280 bytes
    static const size_t MAX_FRAME_SIZE = 4 + 512;
    uint8_t frame[MAX_FRAME_SIZE];

    size_t frameLen = 4 + len;
    if (frameLen > MAX_FRAME_SIZE) {
        return false; // Payload too large
    }

    // Frame format: [type:1][direction:1][length:2][payload:N]
    frame[0] = type;
    frame[1] = direction;
    frame[2] = (len >> 8) & 0xFF;
    frame[3] = len & 0xFF;

    if (len > 0 && payload) {
        memcpy(frame + 4, payload, len);
    }

    return webSocket.sendBIN(frame, frameLen);
}

void PacketLogger::handleAdminCommand(const uint8_t *payload, size_t len)
{
    // Decode ToRadio protobuf
    meshtastic_ToRadio toRadio = meshtastic_ToRadio_init_zero;

    pb_istream_t stream = pb_istream_from_buffer(payload, len);
    if (!pb_decode(&stream, meshtastic_ToRadio_fields, &toRadio)) {
        LOG_WARN("PacketLogger: failed to decode ToRadio: %s", stream.errmsg);
        sendAdminError("Failed to decode ToRadio protobuf");
        return;
    }

    LOG_DEBUG("PacketLogger: ToRadio decoded, payload_variant=%d", toRadio.which_payload_variant);

    // Process based on payload variant
    switch (toRadio.which_payload_variant) {
    case meshtastic_ToRadio_packet_tag: {
        // Handle mesh packet - send it to the mesh
        meshtastic_MeshPacket &p = toRadio.packet;
        LOG_INFO("PacketLogger: admin sending packet to=0x%08x port=%d", p.to, p.decoded.portnum);

        // Use MeshService to send the packet
        service->sendToMesh(packetPool.allocCopy(p), RX_SRC_LOCAL, true);

        // Send success response with a simple FromRadio containing the packet ID
        meshtastic_FromRadio fromRadio = meshtastic_FromRadio_init_zero;
        fromRadio.id = p.id;
        fromRadio.which_payload_variant = meshtastic_FromRadio_packet_tag;
        fromRadio.packet = p;

        uint8_t responseBuf[meshtastic_FromRadio_size];
        size_t responseLen = pb_encode_to_bytes(responseBuf, sizeof(responseBuf), meshtastic_FromRadio_fields, &fromRadio);
        if (responseLen > 0) {
            sendAdminResponse(responseBuf, responseLen);
        }
        break;
    }

    case meshtastic_ToRadio_want_config_id_tag: {
        // Client wants config - stream my_info + all nodes
        uint32_t configNonce = toRadio.want_config_id;
        LOG_INFO("PacketLogger: admin requested config (nonce=%u)", configNonce);

        uint8_t responseBuf[meshtastic_FromRadio_size];
        size_t responseLen;
        uint32_t packetId = 1;

        // 1. Send my_info first
        {
            meshtastic_FromRadio fromRadio = meshtastic_FromRadio_init_zero;
            fromRadio.id = packetId++;
            fromRadio.which_payload_variant = meshtastic_FromRadio_my_info_tag;
            fromRadio.my_info = myNodeInfo;
            responseLen = pb_encode_to_bytes(responseBuf, sizeof(responseBuf), meshtastic_FromRadio_fields, &fromRadio);
            if (responseLen > 0) {
                sendAdminResponse(responseBuf, responseLen);
            }
        }

        // 2. Send all nodes from NodeDB
        for (size_t i = 0; i < nodeDB->getNumMeshNodes(); i++) {
            meshtastic_NodeInfoLite *nodeLite = nodeDB->getMeshNodeByIndex(i);
            if (nodeLite) {
                meshtastic_FromRadio fromRadio = meshtastic_FromRadio_init_zero;
                fromRadio.id = packetId++;
                fromRadio.which_payload_variant = meshtastic_FromRadio_node_info_tag;
                fromRadio.node_info = TypeConversions::ConvertToNodeInfo(nodeLite);
                responseLen = pb_encode_to_bytes(responseBuf, sizeof(responseBuf), meshtastic_FromRadio_fields, &fromRadio);
                if (responseLen > 0) {
                    sendAdminResponse(responseBuf, responseLen);
                }
            }
        }

        // 3. Send config_complete_id to signal end
        {
            meshtastic_FromRadio fromRadio = meshtastic_FromRadio_init_zero;
            fromRadio.id = packetId++;
            fromRadio.which_payload_variant = meshtastic_FromRadio_config_complete_id_tag;
            fromRadio.config_complete_id = configNonce;
            responseLen = pb_encode_to_bytes(responseBuf, sizeof(responseBuf), meshtastic_FromRadio_fields, &fromRadio);
            if (responseLen > 0) {
                sendAdminResponse(responseBuf, responseLen);
            }
        }

        LOG_INFO("PacketLogger: sent %u nodes + config_complete", nodeDB->getNumMeshNodes());
        break;
    }

    case meshtastic_ToRadio_disconnect_tag:
        LOG_INFO("PacketLogger: admin requested disconnect");
        // Just acknowledge, don't actually disconnect
        sendAdminResponse(nullptr, 0);
        break;

    case meshtastic_ToRadio_heartbeat_tag:
        LOG_DEBUG("PacketLogger: admin heartbeat received");
        // Echo back a simple response
        sendAdminResponse(nullptr, 0);
        break;

    default:
        LOG_WARN("PacketLogger: unhandled ToRadio variant %d", toRadio.which_payload_variant);
        sendAdminError("Unsupported ToRadio variant");
        break;
    }
}

bool PacketLogger::sendAdminResponse(const uint8_t *fromRadioBuf, size_t len)
{
    if (len == 0 || fromRadioBuf == nullptr) {
        // Send empty success response
        return sendFrame(PACKET_LOG_MSG_ADMIN_OK, PACKET_LOG_DIR_OUTBOUND, nullptr, 0);
    }
    return sendFrame(PACKET_LOG_MSG_ADMIN_OK, PACKET_LOG_DIR_OUTBOUND, fromRadioBuf, len);
}

bool PacketLogger::sendAdminError(const char *errorMsg)
{
    size_t len = errorMsg ? strlen(errorMsg) : 0;
    return sendFrame(PACKET_LOG_MSG_ADMIN_FAIL, PACKET_LOG_DIR_OUTBOUND, (const uint8_t *)errorMsg, len);
}

#endif // HAS_PACKET_LOGGER
