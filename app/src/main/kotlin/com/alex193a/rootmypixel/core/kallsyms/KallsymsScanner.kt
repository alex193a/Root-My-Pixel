package com.alex193a.rootmypixel.core.kallsyms

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Scans a decompressed Linux ARM64 kernel `Image` for the embedded kallsyms
 * symbol table and resolves symbol addresses.
 *
 * Layout assumption (canonical, produced by scripts/kallsyms.c, all arrays in
 * `.rodata` back-to-back with no padding):
 *
 *   kallsyms_num_syms       u32
 *   kallsyms_offsets        u32[num_syms]     (delta from kallsyms_relative_base)
 *   kallsyms_relative_base  u64               (= _text link address)
 *   kallsyms_names          byte stream       (len-prefixed token codes)
 *   kallsyms_markers        u32[(N+255)/256]
 *   kallsyms_token_table    256 NUL-terminated ASCII strings
 *   kallsyms_token_index    u16[256]
 */
class KallsymsScanner {

    data class SymbolTable(
        val names: ByteArray,
        val tokenTable: ByteArray,
        val tokenIndex: IntArray,
        val addresses: LongArray,
    )

    fun resolve(kernel: ByteArray, required: Set<String>): Map<String, Long> {
        val (tokenTable, tokenIndex) = findTokenTables(kernel)
        val markers = findMarkers(kernel, tokenTable.start)
        // relative_base is a known per-KMI link constant; locate it by content.
        val relBasePos = findRelativeBase(kernel, markers.start)
        val namesStart = relBasePos + 8
        require(namesStart >= 0 && namesStart < markers.start) { "Invalid kallsyms names boundary" }

        // Decode names from namesStart until the markers boundary, collecting
        // symbol count and the names we care about.
        val wanted = mutableMapOf<String, Int>() // name -> symbol index
        val names = ArrayList<Pair<String, Int>>() // name -> offset within names
        var cursor = namesStart
        var index = 0
        while (cursor < markers.start) {
            val (name, next) = KallsymsDecoder.decodeName(kernel, cursor, tokenTable.bytes, tokenIndex)
            if (name in required) wanted[name] = index
            index++
            cursor = next
        }
        require(cursor == markers.start) { "kallsyms names did not end at markers boundary" }
        val numSyms = index
        require(numSyms > 0) { "No symbols decoded" }

        // Backward from namesStart: relative_base (8), offsets (N*4), num_syms (4).
        val offsetsEnd = relBasePos
        val offsetsStart = offsetsEnd - numSyms * 4
        require(offsetsStart >= 4) { "kallsyms offsets out of bounds" }
        require(kernel.u32(offsetsStart - 4) == numSyms) { "kallsyms num_syms mismatch" }

        val relBase = kernel.u64(relBasePos)
        val base = relBase // _text link address == image base for these GKI kernels
        val out = HashMap<String, Long>(wanted.size)
        for ((name, i) in wanted) {
            val delta = kernel.u32(offsetsStart + i * 4).toLong() and 0xffffffffL
            // Image-relative offset: symbol VA - base. offsets[] are deltas from
            // relBase, so image offset = (relBase - base) + delta = delta.
            out[name] = delta
        }
        return out
    }

    private data class TokenRange(val start: Int, val bytes: ByteArray)

    private fun findTokenTables(kernel: ByteArray): Pair<TokenRange, IntArray> {
        val table = findTokenTable(kernel)
        // token_index follows token_table immediately.
        val idxStart = table.start + table.bytes.size
        val tokenIndex = IntArray(256)
        for (i in 0 until 256) tokenIndex[i] = kernel.u16(idxStart + i * 2)
        // Validate: offsets into the token table, monotonic.
        require(tokenIndex.all { it in 0 until table.bytes.size }) { "Invalid kallsyms token index" }
        for (i in 1 until tokenIndex.size) require(tokenIndex[i] >= tokenIndex[i - 1]) { "kallsyms token index not monotonic" }
        return table to tokenIndex
    }

    private fun findTokenTable(kernel: ByteArray): TokenRange {
        // Token table: 256 NUL-terminated ASCII strings, then immediately the
        // 256-entry u16 token index. Validate both as one unit to avoid false
        // positives; the combined block is highly distinctive.
        var best: TokenRange? = null
        var bestMaxLen = 0
        for (start in 0 until kernel.size) {
            if (start + 512 + 512 > kernel.size) break
            var p = start
            var strings = 0
            var printable = 0
            var maxLen = 0
            while (strings < 256 && p < kernel.size) {
                val end = kernel.indexOfZero(p)
                if (end < 0) break
                val len = end - p
                if (len > 64) break
                for (i in p until end) if (kernel[i].toInt() in 32..126) printable++
                if (len > maxLen) maxLen = len
                p = end + 1
                strings++
            }
            if (strings != 256) continue
            val tableSize = p - start
            if (tableSize !in 512..16384 || printable < 128) continue
            val idxStart = start + tableSize
            if (idxStart + 512 > kernel.size) continue
            var ok = true
            for (i in 0 until 256) {
                val v = kernel.u16(idxStart + i * 2)
                if (v !in 0 until tableSize) { ok = false; break }
                if (i > 0 && v < kernel.u16(idxStart + (i - 1) * 2)) { ok = false; break }
            }
            if (!ok) continue
            if (kernel.u16(idxStart) != 0) continue // first token is the empty string
            // Last index must point at a plausible end of the table.
            val last = kernel.u16(idxStart + 255 * 2)
            if (tableSize - last > 64) continue
            val range = TokenRange(start, kernel.copyOfRange(start, p))
            // Prefer the block with the longest real strings (more signal).
            if (best == null || maxLen > bestMaxLen) {
                best = range
                bestMaxLen = maxLen
            }
        }
        return best ?: error("kallsyms token table not found")
    }

    private data class MarkerRange(val start: Int)

    private fun findMarkers(kernel: ByteArray, tokenTableStart: Int): MarkerRange {
        // markers end at token_table (contiguous). The first marker is 0 and
        // markers are non-decreasing. The last marker can end exactly at the
        // token table (which need not be 4-byte aligned), so consider both
        // aligned starts and the final 4 bytes right before token_table.
        val ends = listOf(tokenTableStart, tokenTableStart - (tokenTableStart % 4))
        for (end in ends.distinct()) {
            if (end - 4 < 0) continue
            for (i in end - 4 downTo maxOf(0, end - 4096) step 4) {
                if (kernel.u32(i) != 0) continue
                var ok = true
                var prev = 0
                var j = i
                while (j + 4 <= end) {
                    val v = kernel.u32(j)
                    if (v < prev) { ok = false; break }
                    prev = v
                    j += 4
                }
                if (ok) return MarkerRange(i)
            }
        }
        error("kallsyms markers not found")
    }

    private fun findRelativeBase(kernel: ByteArray, markersStart: Int): Int {
        // Scan forward for the per-KMI _text link address immediately followed
        // by a plausible names region ending at markersStart.
        val candidates = longArrayOf(
            0xffffffc008000000UL.toLong(), // 6.1
            0xffffffc080000000UL.toLong(), // 6.6
        )
        for (pos in 0 until markersStart - 8) {
            val v = kernel.u64(pos)
            if (v in candidates) return pos
        }
        error("kallsyms_relative_base not found")
    }
}

private fun ByteArray.indexOfZero(from: Int): Int {
    for (i in from until size) if (this[i].toInt() == 0) return i
    return -1
}

private fun ByteArray.u16(offset: Int): Int =
    (this[offset].toInt() and 255) or ((this[offset + 1].toInt() and 255) shl 8)

private fun ByteArray.u32(offset: Int): Int =
    (this[offset].toInt() and 255) or ((this[offset + 1].toInt() and 255) shl 8) or
        ((this[offset + 2].toInt() and 255) shl 16) or ((this[offset + 3].toInt() and 255) shl 24)

private fun ByteArray.u64(offset: Int): Long {
    val buf = ByteBuffer.wrap(this, offset, 8).order(ByteOrder.LITTLE_ENDIAN)
    return buf.long
}
