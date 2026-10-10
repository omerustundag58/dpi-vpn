// SPDX-License-Identifier: GPL-3.0-or-later
// VpnService gövdesi: TUN kurulumu, paket döngüsü, TCP/UDP/ICMP aktarma,
//! JNI record-split, istatistik yayını, ön-servis bildirimi. Tek APK, minSdk 26.
package com.dpivpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.DatagramChannel
import java.nio.channels.SocketChannel
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

class DpiVpnService : VpnService() {

    companion object {
        const val ACTION_UPDATE = "com.dpivpn.STATE_UPDATE"
        private const val NOTIF_ID = 1
        private const val CH_ID = "dpi_vpn"
        private val PROFILE_DELAY = longArrayOf(4, 3, 5, 3, 0, 1, 0, 5)
    }

    private var tun: ParcelFileDescriptor? = null
    private var out: FileOutputStream? = null
    private val running = AtomicBoolean(false)
    private val conns = ConcurrentHashMap<String, TcpConn>()
    private val udpMap = ConcurrentHashMap<String, DatagramChannel>()
    private val bytesUp = AtomicLong(0)
    private val bytesDown = AtomicLong(0)
    private var startMs = 0L
    private var mode = 0
    private var profile = 0

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == "DISCONNECT") {
            shutdown()
            stopSelf()
            return START_NOT_STICKY
        }
        profile = (intent?.getIntExtra("profile", 0) ?: 0).coerceIn(0, 7)
        mode = (intent?.getIntExtra("mode", 0) ?: 0).coerceIn(0, 2)
        val customDns = intent?.getBooleanExtra("custom_dns", false) ?: false
        @Suppress("UNCHECKED_CAST")
        val allowed = intent?.getStringArrayListExtra("allowed_apps") ?: arrayListOf()
        startTun(customDns, allowed)
        return START_STICKY
    }

    private fun startTun(customDns: Boolean, allowed: ArrayList<String>) {
        if (running.get()) return
        val b = Builder()
            .setSession("DPI VPN")
            .addAddress("10.0.0.2", 32)
            .addDnsServer(if (customDns) "1.1.1.1" else "8.8.8.8")
            .addRoute("0.0.0.0", 0)
            .setMtu(1500)
        for (pkg in allowed) {
            try { b.addAllowedApplication(pkg) } catch (_: Exception) {}
        }
        tun = try { b.establish() } catch (_: Exception) { return }
        startFg()
        running.set(true)
        startMs = System.currentTimeMillis()
        val fd = tun ?: return
        thread(name = "tun-read", isDaemon = true) { readLoop(FileInputStream(fd.fileDescriptor)) }
        thread(name = "stats", isDaemon = true) { statsLoop() }
    }

    private fun startFg() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            nm.createNotificationChannel(NotificationChannel(CH_ID, "DPI VPN", NotificationManager.IMPORTANCE_LOW))
        }
        val pi = PendingIntent.getActivity(this, 0, Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
        val nb = if (Build.VERSION.SDK_INT >= 26)
            Notification.Builder(this, CH_ID)
        else
            @Suppress("DEPRECATION") Notification.Builder(this)
        val notif = nb.setContentTitle("DPI VPN")
            .setContentText("Koruma aktif")
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pi)
            .build()
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(NOTIF_ID, notif, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            @Suppress("DEPRECATION") startForeground(NOTIF_ID, notif)
        }
    }

    private fun statsLoop() {
        while (running.get()) {
            try { Thread.sleep(2000) } catch (_: InterruptedException) { break }
            sendBroadcast(Intent(ACTION_UPDATE).apply {
                putExtra("bytes_up", bytesUp.get())
                putExtra("bytes_down", bytesDown.get())
                putExtra("duration_sec", (System.currentTimeMillis() - startMs) / 1000)
                putExtra("running", true)
                setPackage(packageName)
            })
        }
    }

    private fun readLoop(input: FileInputStream) {
        val buf = ByteArray(32767)
        while (running.get()) {
            val n = try { input.read(buf) } catch (_: Exception) { break }
            if (n <= 0) continue
            try { dispatch(buf, n) } catch (_: Exception) {}
        }
    }

    private fun dispatch(pkt: ByteArray, n: Int) {
        if (n < 20) return
        if ((pkt[0].toInt() ushr 4) != 4) return // yalnızca IPv4
        val ihl = (pkt[0].toInt() and 0x0F) * 4
        if (n < ihl) return
        val proto = pkt[9].toInt() and 0xFF
        val srcIp = IpUtil.bytesToIp(pkt, 12)
        val dstIp = IpUtil.bytesToIp(pkt, 16)
        when (proto) {
            6 -> handleTcp(pkt, n, ihl, srcIp, dstIp)
            17 -> handleUdp(pkt, n, ihl, srcIp, dstIp)
            1 -> handleIcmp(pkt, n, ihl, srcIp, dstIp)
        }
    }

    // ---------- TCP ----------
    private fun handleTcp(pkt: ByteArray, n: Int, ihl: Int, srcIp: Int, dstIp: Int) {
        if (n < ihl + 20) return
        val srcPort = IpUtil.getU16(pkt, ihl)
        val dstPort = IpUtil.getU16(pkt, ihl + 2)
        val seq = IpUtil.getU32(pkt, ihl + 4)
        val flags = pkt[ihl + 13].toInt() and 0xFF
        val hdrLen = ((pkt[ihl + 12].toInt() ushr 4) and 0xF) * 4
        if (hdrLen < 20 || n < ihl + hdrLen) return
        val payloadOff = ihl + hdrLen
        val payloadLen = n - payloadOff
        val key = "$srcIp:$srcPort>$dstIp:$dstPort"
        val syn = flags and 0x02 != 0
        val ack = flags and 0x10 != 0
        val fin = flags and 0x01 != 0
        val rst = flags and 0x04 != 0

        var conn = conns[key]
        if (conn == null) {
            if (!syn || ack) return // veri ortasında katıldık — kuramayız
            openTcp(key, srcIp, srcPort, dstIp, dstPort, seq, pkt, ihl, hdrLen)
            return
        }
        if (conn.closed) return
        if (rst) { closeConn(conn); return }
        if (payloadLen > 0) {
            var start = seq
            var off = payloadOff
            var len = payloadLen
            // yeniden gönderim çakışmasını kırp
            if (start < conn.clientSeq) {
                val skip = (conn.clientSeq - start).toInt()
                if (skip >= len) { sendAck(conn); return }
                start += skip; off += skip; len -= skip
            }
            if (start != conn.clientSeq) return // boşluk — bekle
            val data = pkt.copyOfRange(off, off + len)
            try {
                if (!conn.firstPayloadDone && dstPort == 443 && isTlsHello(data)) {
                    sendSplit(conn, data)
                } else {
                    writeAll(conn.channel, data)
                }
                conn.firstPayloadDone = true
            } catch (_: Exception) { closeConn(conn); return }
            conn.clientSeq += len
            conn.bytesUp.addAndGet(len.toLong())
            bytesUp.addAndGet(len.toLong())
            sendAck(conn)
        }
        if (fin) {
            conn.clientSeq++
            sendFinAck(conn)
            closeConn(conn)
        }
    }

    private fun openTcp(key: String, srcIp: Int, srcPort: Int, dstIp: Int, dstPort: Int,
                        seq: Long, pkt: ByteArray, ihl: Int, hdrLen: Int) {
        val ch = try {
            SocketChannel.open().also {
                protect(it.socket())
                it.configureBlocking(true)
                it.socket().tcpNoDelay = true
                it.connect(InetSocketAddress(InetAddress.getByAddress(ipBytes(dstIp)), dstPort), 8000)
            }
        } catch (_: Exception) {
            // hedefe ulaşılamadı — istemciye RST
            sendTcp(srcIp, dstIp, srcPort, dstPort, 0, seq + 1, 0x14, byteArrayOf())
            return
        }
        val conn = TcpConn(key, srcIp, srcPort, dstIp, dstPort, ch, seq + 1)
        conns[key] = conn
        val mss = parseMss(pkt, ihl, hdrLen).coerceAtMost(1460)
        sendTcp(srcIp, dstIp, srcPort, dstPort, conn.ourSeq, conn.clientSeq, 0x12,
            byteArrayOf(), mssOption(mss))
        conn.ourSeq++
        thread(name = "tcp-$dstPort", isDaemon = true) { relayToTun(conn) }
    }

    private fun relayToTun(conn: TcpConn) {
        val buf = ByteBuffer.allocate(16384)
        try {
            while (!conn.closed) {
                buf.clear()
                val n = conn.channel.read(buf)
                if (n <= 0) break
                buf.flip()
                val data = ByteArray(n)
                buf.get(data)
                conn.bytesDown.addAndGet(n.toLong())
                bytesDown.addAndGet(n.toLong())
                sendData(conn, data)
            }
        } catch (_: Exception) {
        } finally {
            if (!conn.closed) {
                sendFin(conn)
                closeConn(conn)
            }
        }
    }

    private fun isTlsHello(data: ByteArray): Boolean =
        data.size >= 6 && data[0] == 0x16.toByte() && data[5] == 0x01.toByte()

    private fun sendSplit(conn: TcpConn, data: ByteArray) {
        val delayMs = PROFILE_DELAY[profile]
        val parts: Array<ByteArray> = when (mode) {
            2 -> DpiJni.splitTcp(data, 0L)          // Parçala: düz TCP bölme
            else -> DpiJni.splitRecords(data)       // Hızlı/Dengeli: record-split
        }
        val delay = if (mode == 1) delayMs else 0L
        for ((i, p) in parts.withIndex()) {
            if (p.isNotEmpty()) writeAll(conn.channel, p)
            if (i == 0 && delay > 0 && parts.size > 1) {
                try { Thread.sleep(delay) } catch (_: InterruptedException) {}
            }
        }
    }

    private fun writeAll(ch: SocketChannel, data: ByteArray) {
        var bb = ByteBuffer.wrap(data)
        while (bb.hasRemaining()) ch.write(bb)
    }

    private fun sendAck(conn: TcpConn) =
        sendTcp(conn.srcIp, conn.dstIp, conn.srcPort, conn.dstPort, conn.ourSeq, conn.clientSeq, 0x10, byteArrayOf())

    private fun sendData(conn: TcpConn, data: ByteArray) {
        var off = 0
        while (off < data.size) {
            val chunk = minOf(1400, data.size - off)
            sendTcp(conn.srcIp, conn.dstIp, conn.srcPort, conn.dstPort, conn.ourSeq, conn.clientSeq,
                0x18, data.copyOfRange(off, off + chunk))
            conn.ourSeq += chunk
            off += chunk
        }
    }

    private fun sendFin(conn: TcpConn) {
        sendTcp(conn.srcIp, conn.dstIp, conn.srcPort, conn.dstPort, conn.ourSeq, conn.clientSeq, 0x11, byteArrayOf())
        conn.ourSeq++
    }

    private fun sendFinAck(conn: TcpConn) {
        sendTcp(conn.srcIp, conn.dstIp, conn.srcPort, conn.dstPort, conn.ourSeq, conn.clientSeq, 0x11, byteArrayOf())
        conn.ourSeq++
    }

    /** src=uzak(sunucu gibi), dst=istemci: TUN'a yazılan paket. */
    private fun sendTcp(srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int,
                        seq: Long, ack: Long, flags: Int, payload: ByteArray) {
        val ip = ByteArray(20)
        ip[0] = 0x45; ip[1] = 0; ip[8] = 64; ip[9] = 6
        IpUtil.ipToBytes(srcIp, ip, 12); IpUtil.ipToBytes(dstIp, ip, 16)
        val tcp = ByteArray(20 + payload.size)
        IpUtil.putU16(tcp, 0, srcPort); IpUtil.putU16(tcp, 2, dstPort)
        IpUtil.putU32(tcp, 4, seq); IpUtil.putU32(tcp, 8, ack)
        tcp[12] = 0x50; tcp[13] = flags.toByte(); IpUtil.putU16(tcp, 14, 65535)
        payload.copyInto(tcp, 20)
        val csum = IpUtil.tcpChecksum(srcIp, dstIp, tcp, 0, tcp.size)
        IpUtil.putU16(tcp, 16, csum)
        val total = 20 + tcp.size
        IpUtil.putU16(ip, 2, total)
        IpUtil.putU16(ip, 4, (Math.random() * 65535).toInt())
        IpUtil.putU16(ip, 10, IpUtil.ipChecksum(ip, 0, 5))
        writeTun(ip + tcp)
    }

    private fun mssOption(mss: Int): ByteArray {
        val o = ByteArray(4)
        o[0] = 2; o[1] = 4
        IpUtil.putU16(o, 2, mss)
        return o
    }

    private fun closeConn(conn: TcpConn) {
        if (conn.closed) return
        conn.closed = true
        conns.remove(conn.key)
        try { conn.channel.close() } catch (_: Exception) {}
    }

    private fun ipBytes(ip: Int): ByteArray {
        val b = ByteArray(4)
        IpUtil.ipToBytes(ip, b, 0)
        return b
    }

    // ---------- UDP (DNS + genel: ses trafiği dahil) ----------
    private fun handleUdp(pkt: ByteArray, n: Int, ihl: Int, srcIp: Int, dstIp: Int) {
        if (n < ihl + 8) return
        val srcPort = IpUtil.getU16(pkt, ihl)
        val dstPort = IpUtil.getU16(pkt, ihl + 2)
        val ulen = IpUtil.getU16(pkt, ihl + 4)
        if (ulen < 8 || n < ihl + ulen) return
        val payload = pkt.copyOfRange(ihl + 8, ihl + ulen)
        val key = "$srcIp:$srcPort>$dstIp:$dstPort"
        var ch = udpMap[key]
        if (ch == null || !ch.isOpen) {
            ch = try {
                DatagramChannel.open().also {
                    protect(it.socket())
                    it.configureBlocking(true)
                    it.connect(InetSocketAddress(InetAddress.getByAddress(ipBytes(dstIp)), dstPort))
                }
            } catch (_: Exception) { return }
            udpMap[key] = ch
            val cch = ch
            thread(name = "udp-$dstPort", isDaemon = true) {
                val buf = ByteBuffer.allocate(4096)
                var idle = 0
                try {
                    cch.socket().soTimeout = 5000
                    while (running.get() && idle < 6) {
                        buf.clear()
                        val m = try { cch.read(buf) } catch (_: Exception) { idle++; continue }
                        if (m <= 0) { idle++; continue }
                        idle = 0
                        buf.flip()
                        val data = ByteArray(m)
                        buf.get(data)
                        bytesDown.addAndGet(m.toLong())
                        sendUdp(srcIp, dstIp, srcPort, dstPort, data)
                    }
                } catch (_: Exception) {
                } finally {
                    udpMap.remove(key)
                    try { cch.close() } catch (_: Exception) {}
                }
            }
        }
        try {
            ch.write(ByteBuffer.wrap(payload))
            bytesUp.addAndGet(payload.size.toLong())
        } catch (_: Exception) {
            udpMap.remove(key)
        }
    }

    private fun sendUdp(srcIp: Int, dstIp: Int, srcPort: Int, dstPort: Int, payload: ByteArray) {
        val ip = ByteArray(20)
        ip[0] = 0x45; ip[1] = 0; ip[8] = 64; ip[9] = 17
        IpUtil.ipToBytes(srcIp, ip, 12); IpUtil.ipToBytes(dstIp, ip, 16)
        val u = ByteArray(8 + payload.size)
        IpUtil.putU16(u, 0, srcPort); IpUtil.putU16(u, 2, dstPort)
        IpUtil.putU16(u, 4, u.size) // checksum 0 (IPv4'te geçerli)
        payload.copyInto(u, 8)
        IpUtil.putU16(ip, 2, 20 + u.size)
        IpUtil.putU16(ip, 4, (Math.random() * 65535).toInt())
        IpUtil.putU16(ip, 10, IpUtil.ipChecksum(ip, 0, 5))
        writeTun(ip + u)
    }

    // ---------- ICMP ping ----------
    private fun handleIcmp(pkt: ByteArray, n: Int, ihl: Int, srcIp: Int, dstIp: Int) {
        if (n < ihl + 8) return
        if (pkt[ihl] != 8.toByte()) return // yalnızca echo request
        val len = n - ihl
        val rep = pkt.copyOfRange(ihl, n)
        rep[0] = 0 // echo reply
        rep[2] = 0; rep[3] = 0
        var sum = 0
        var i = 0
        while (i < len - 1) {
            sum += ((rep[i].toInt() and 0xFF) shl 8) or (rep[i + 1].toInt() and 0xFF)
            i += 2
        }
        if (len % 2 == 1) sum += (rep[len - 1].toInt() and 0xFF) shl 8
        while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
        val c = sum.inv() and 0xFFFF
        rep[2] = (c ushr 8).toByte(); rep[3] = c.toByte()
        val ip = ByteArray(20)
        ip[0] = 0x45; ip[1] = 0; ip[8] = 64; ip[9] = 1
        IpUtil.ipToBytes(dstIp, ip, 12); IpUtil.ipToBytes(srcIp, ip, 16)
        IpUtil.putU16(ip, 2, 20 + len)
        IpUtil.putU16(ip, 4, (Math.random() * 65535).toInt())
        IpUtil.putU16(ip, 10, IpUtil.ipChecksum(ip, 0, 5))
        writeTun(ip + rep)
    }

    @Synchronized
    private fun writeTun(data: ByteArray) {
        try { out ?: FileOutputStream(tun?.fileDescriptor).also { out = it }; out?.write(data) } catch (_: Exception) {}
    }

    private fun shutdown() {
        running.set(false)
        for (c in conns.values) try { c.channel.close() } catch (_: Exception) {}
        conns.clear()
        for (u in udpMap.values) try { u.close() } catch (_: Exception) {}
        udpMap.clear()
        try { tun?.close() } catch (_: Exception) {}
        tun = null
        out = null
        sendBroadcast(Intent(ACTION_UPDATE).apply {
            putExtra("bytes_up", bytesUp.get())
            putExtra("bytes_down", bytesDown.get())
            putExtra("duration_sec", 0L)
            putExtra("running", false)
            setPackage(packageName)
        })
        try { stopForeground(STOP_FOREGROUND_REMOVE) } catch (_: Exception) {}
    }

    override fun onDestroy() { shutdown(); super.onDestroy() }
    override fun onRevoke() { shutdown(); super.onRevoke() }
}
