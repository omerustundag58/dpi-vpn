// SPDX-License-Identifier: GPL-3.0-or-later
// TUN TCP/UDP aktarıcı: IP parse, checksum, bağlantı takibi, JNI bölme.
//! VpnService'in veri düzlemi; Android sürümünden bağımsız saf ağ kodu.
package com.dpivpn

import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/** IPv4 + TCP checksum yardımcıları. */
object IpUtil {
    fun ipChecksum(buf: ByteArray, off: Int, ihl: Int): Int {
        var sum = 0
        var i = off
        val end = off + ihl * 4
        while (i < end) {
            sum += ((buf[i].toInt() and 0xFF) shl 8) or (buf[i + 1].toInt() and 0xFF)
            if (sum > 0xFFFF) sum = (sum and 0xFFFF) + 1
            i += 2
        }
        return sum.inv() and 0xFFFF
    }

    fun tcpChecksum(srcIp: Int, dstIp: Int, tcp: ByteArray, off: Int, len: Int): Int {
        var sum = (srcIp ushr 16) + (srcIp and 0xFFFF) + (dstIp ushr 16) + (dstIp and 0xFFFF) + 6 + len
        var i = off
        val end = off + len - 1
        while (i < end) {
            sum += ((tcp[i].toInt() and 0xFF) shl 8) or (tcp[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (len % 2 == 1) sum += (tcp[off + len - 1].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        return sum.inv() and 0xFFFF
    }

    fun bytesToIp(b: ByteArray, o: Int): Int =
        ((b[o].toInt() and 0xFF) shl 24) or ((b[o + 1].toInt() and 0xFF) shl 16) or
            ((b[o + 2].toInt() and 0xFF) shl 8) or (b[o + 3].toInt() and 0xFF)

    fun ipToBytes(ip: Int, b: ByteArray, o: Int) {
        b[o] = (ip ushr 24).toByte(); b[o + 1] = (ip ushr 16).toByte()
        b[o + 2] = (ip ushr 8).toByte(); b[o + 3] = ip.toByte()
    }

    fun putU16(b: ByteArray, o: Int, v: Int) { b[o] = (v ushr 8).toByte(); b[o + 1] = v.toByte() }
    fun putU32(b: ByteArray, o: Int, v: Long) {
        b[o] = (v ushr 24).toByte(); b[o + 1] = (v ushr 16).toByte()
        b[o + 2] = (v ushr 8).toByte(); b[o + 3] = v.toByte()
    }

    fun getU16(b: ByteArray, o: Int): Int = ((b[o].toInt() and 0xFF) shl 8) or (b[o + 1].toInt() and 0xFF)
    fun getU32(b: ByteArray, o: Int): Long =
        ((b[o].toLong() and 0xFF) shl 24) or ((b[o + 1].toLong() and 0xFF) shl 16) or
            ((b[o + 2].toLong() and 0xFF) shl 8) or (b[o + 3].toLong() and 0xFF)
}

/** Tek TCP bağlantısı: istemci SYN'den FIN'e kadar durum. */
class TcpConn(
    val key: String,
    val srcIp: Int, val srcPort: Int, val dstIp: Int, val dstPort: Int,
    val channel: java.nio.channels.SocketChannel,
    var clientSeq: Long, // istemciden beklenen seq (veri başlangıcı)
    var ourSeq: Long = (Math.random() * Int.MAX_VALUE).toLong(),
    @Volatile var closed: Boolean = false,
) {
    val bytesUp = AtomicLong(0)
    val bytesDown = AtomicLong(0)
    var firstPayloadDone = false
}

/** Ham SYN paketinden MSS değerini okur (yoksa 1460). */
fun parseMss(tcp: ByteArray, off: Int, headerLen: Int): Int {
    var i = off + 20
    val end = off + headerLen
    while (i < end) {
        val kind = tcp[i].toInt() and 0xFF
        if (kind == 0) break
        if (kind == 1) { i++; continue }
        if (i + 1 >= end) break
        val len = tcp[i + 1].toInt() and 0xFF
        if (len < 2 || i + len > end) break
        if (kind == 2 && len == 4) {
            return ((tcp[i + 2].toInt() and 0xFF) shl 8) or (tcp[i + 3].toInt() and 0xFF)
        }
        i += len
    }
    return 1460
}
