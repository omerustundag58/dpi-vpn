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
}
