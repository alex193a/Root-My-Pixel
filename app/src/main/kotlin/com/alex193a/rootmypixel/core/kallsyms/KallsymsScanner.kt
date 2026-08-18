package com.alex193a.rootmypixel.core.kallsyms

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Scans a decompressed kernel for kallsyms' token tables and names. */
class KallsymsScanner {
    data class SymbolTable(val names: ByteArray, val tokenTable: ByteArray, val tokenIndex: IntArray, val addresses: LongArray)

    fun scan(kernel: ByteArray): SymbolTable {
        val token = findTokenTable(kernel)
        val index = findTokenIndex(kernel, token.first)
        val count = findSymbolCount(kernel, index.first)
        val names = findNames(kernel, index.first, count)
        val addresses = findAddresses(kernel, names.first, count)
        return SymbolTable(names.second, token.second, index.second, addresses)
    }

    fun resolve(kernel: ByteArray, required: Set<String>): Map<String, Long> {
        val table = scan(kernel)
        val names = KallsymsDecoder.decodeAll(table.names, table.addresses.size, table.tokenTable, table.tokenIndex)
        return names.mapIndexedNotNull { i, name -> if (name in required) name to table.addresses[i] else null }.toMap()
    }

    private fun findTokenTable(kernel: ByteArray): Pair<Int, ByteArray> {
        // Token tables contain 256 NUL-terminated strings. Locate a run with a
        // valid total size and enough printable bytes to avoid random matches.
        for (start in 0 until kernel.size - 512) {
            var p = start; var strings = 0; var printable = 0
            while (strings < 256 && p < kernel.size) {
                val end = kernel.indexOfZero(p)
                if (end < 0 || end - p > 64) break
                for (i in p until end) if (kernel[i].toInt() in 32..126) printable++
                p = end + 1; strings++
            }
            if (strings == 256 && printable > 128) return start to kernel.copyOfRange(start, p)
        }
        error("kallsyms token table not found")
    }

    private fun findTokenIndex(kernel: ByteArray, tableStart: Int): Pair<Int, IntArray> {
        for (start in 0 until tableStart - 512 step 2) {
            val indices = IntArray(256)
            var valid = true
            for (i in indices.indices) {
                val value = kernel.u16(start + i * 2)
                if (value >= tableStart - start) { valid = false; break }
                indices[i] = value
            }
            var ordered = valid
            for (i in 0 until indices.size - 1) if (indices[i] > indices[i + 1]) ordered = false
            if (ordered && indices[0] == 0) return start to indices
        }
        error("kallsyms token index not found")
    }

    private fun findSymbolCount(kernel: ByteArray, tokenIndexStart: Int): Int {
        for (p in tokenIndexStart - 8 downTo 0 step 4) {
            val n = kernel.u32(p)
            if (n in 1..2_000_000 && tokenIndexStart - p > n / 4) return n
        }
        error("kallsyms symbol count not found")
    }

    private fun findNames(kernel: ByteArray, tokenIndexStart: Int, count: Int): Pair<Int, ByteArray> {
        // The names stream is immediately before markers and token metadata.
        for (start in tokenIndexStart - 1 downTo 0) {
            var p = start; var ok = true
            repeat(minOf(count, 32)) {
                if (p >= tokenIndexStart) { ok = false; return@repeat }
                val length = kernel[p].toInt() and 255
                if (length == 0 || p + length + 1 > tokenIndexStart) { ok = false; return@repeat }
                p += length + 1
            }
            if (ok) return start to kernel.copyOfRange(start, tokenIndexStart)
        }
        error("kallsyms names not found")
    }

    private fun findAddresses(kernel: ByteArray, namesStart: Int, count: Int): LongArray {
        val bytes = count * 4
        for (start in namesStart - 64 downTo 0 step 4) {
            if (start + bytes > namesStart) continue
            val values = LongArray(count) { kernel.u32(start + it * 4).toLong() and 0xffffffffL }
            if (values.take(32).zipWithNext().all { it.first <= it.second }) return values
        }
        error("kallsyms addresses not found")
    }
}

private fun ByteArray.indexOfZero(from: Int): Int = (from until size).firstOrNull { this[it].toInt() == 0 } ?: -1
private fun ByteArray.u16(offset: Int): Int = (this[offset].toInt() and 255) or ((this[offset + 1].toInt() and 255) shl 8)
private fun ByteArray.u32(offset: Int): Int = (this[offset].toInt() and 255) or ((this[offset + 1].toInt() and 255) shl 8) or ((this[offset + 2].toInt() and 255) shl 16) or ((this[offset + 3].toInt() and 255) shl 24)
