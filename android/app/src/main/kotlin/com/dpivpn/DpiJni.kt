// SPDX-License-Identifier: GPL-3.0-or-later
// JNI köprüsü: dpi_core kitaplığını yükleyip paket bölme işlevlerini dışa açar.
package com.dpivpn

object DpiJni {
    init {
        System.loadLibrary("dpi_core")
    }

    external fun dpiVersion(): Int
    external fun shouldProcess(port: Int, first: ByteArray): Boolean
    external fun splitRecords(packet: ByteArray): Array<ByteArray>
    external fun splitTcp(packet: ByteArray, delayMs: Long): Array<ByteArray>
    /** İnce ayar: cut 0=orta 1=önce, reverse 1=ters sıra. */
    external fun splitCustom(packet: ByteArray, delayMs: Long, cut: Int, reverse: Int): Array<ByteArray>
    /** QUIC Initial bölme: 2 datagram döner (bölünemezse aynen tek). */
    external fun splitQuic(packet: ByteArray): Array<ByteArray>
    /** Otomatik taktik: pakete göre en iyi bölme. */
    external fun splitAuto(packet: ByteArray): Array<ByteArray>
    /** SNI muaf listede mi (devlet/yerli)? O zaman bölmeden direkt ilet. */
    external fun isExcluded(packet: ByteArray): Boolean
}
