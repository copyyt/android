package com.copyyt.android.app

import com.copyyt.android.sync.SocketConnection
import com.copyyt.android.sync.SocketListener
import io.socket.client.Ack
import io.socket.client.IO
import io.socket.client.Socket
import io.socket.engineio.client.transports.WebSocket
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.json.JSONObject

/**
 * Socket.IO v4 session using the same device-auth handshake as the
 * extension. Automatic reconnection is off: the engine reconnects itself so
 * each new connection carries a freshly refreshed access token.
 */
class SocketIoConnection(
    url: String,
    accessToken: String,
    private val listener: SocketListener,
) : SocketConnection {
    private val socket: Socket = IO.socket(
        url,
        IO.Options.builder()
            .setTransports(arrayOf(WebSocket.NAME))
            .setReconnection(false)
            .setAuth(mapOf("token" to accessToken))
            .build(),
    )
    @Volatile private var closedByClient = false
    @Volatile private var authFailed = false

    init {
        socket.on("auth:challenge") { args ->
            val payload = args.firstOrNull() as? JSONObject ?: return@on
            val id = socket.id() ?: return@on
            listener.onChallenge(id, payload.optString("challenge"))
        }
        socket.on("auth:ready") { listener.onReady() }
        socket.on("auth:failure") { authFailed = true }
        socket.on("clipboard:item") { args ->
            (args.firstOrNull() as? JSONObject)?.let { listener.onItem(it.toString()) }
        }
        socket.on(Socket.EVENT_DISCONNECT) { notifyClosed() }
        socket.on(Socket.EVENT_CONNECT_ERROR) { notifyClosed() }
        socket.connect()
    }

    private var notified = false

    @Synchronized
    private fun notifyClosed() {
        if (notified || closedByClient) return
        notified = true
        listener.onClosed(authFailed)
    }

    override fun close() {
        closedByClient = true
        socket.off()
        socket.disconnect()
    }

    override fun emitDeviceAuth(payload: JsonObject) {
        socket.emit("auth:device", JSONObject(payload.toString()))
    }

    override fun publish(payload: JsonObject, onAck: (JsonObject?) -> Unit) {
        socket.emit(
            "clipboard:publish",
            arrayOf<Any>(JSONObject(payload.toString())),
            Ack { args ->
                val ack = (args.firstOrNull() as? JSONObject)?.let {
                    runCatching { Json.parseToJsonElement(it.toString()).jsonObject }.getOrNull()
                }
                onAck(ack)
            },
        )
    }
}
