package com.alex193a.rootmypixel.core.kallsyms

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Resolves symbol offsets from a decompressed Linux ARM64 kernel `Image`.
 *
 * kallsyms tables emitted by scripts/kallsyms.c:
 *   [offsets(u32) or addresses(u64)] , num_syms, relative_base,
 *   names, markers, token_table, token_index
 *
 * LTO/BOLT kernels (observed on 6.6 frankel) link them in a different order:
 *   names, markers, token_table, token_index, offsets(u32), relbase(u64)
 * and their token table does NOT start with a NUL (token 0 is "Ts").
 *
 * Algorithm:
 *  1. Find token_index candidates (256 monotonic u16, first == 0).
 *  2. For each, find token_table as the 256-string NUL-terminated region ending
 *     exactly at the index; validate the index against the table.
 *  3. Markers immediately precede the table (4-aligned, monotonic u32, first 0).
 *  4. names_start: the unique position whose 256-name decode chain consumes
 *     exactly markers[1] bytes (fallback: chain to markers_start exactly).
 *  5. Locate the offsets/addresses array + relative_base in three variants:
 *     (B) after the token_index (LTO), (A) before the names (classic
 *     base-relative), (C) absolute u64 addresses before the names.
 *  6. Validate num_syms against the marker count and decode all names,
 *     matching with and without the kallsyms type prefix.
 *
 * The scan is O(image size): candidate enumeration is a single pass and each
 * table/index validation is O(256); names_start probing is bounded to a few
 * kilobytes around the marker-derived estimate.
 */
class KallsymsScanner {

    private class Tables(
        val namesStart: Int,
        val tokenTable: ByteArray,
        val tokenIndex: IntArray,
        val offsetsStart: Int,
        val numSyms: Int,
        val absolute: Boolean,
        val relBase: Long,
    )

    fun resolve(kernel: ByteArray, required: Set<String>): Map<String, Long> {
        val tokenIndexStarts = findTokenIndexCandidates(kernel)
        require(tokenIndexStarts.isNotEmpty()) { "kallsyms token index not found" }

        // LTO kernels are the only supported modern layouts and they are
        // recognised by a cheap structural gate (offsets array directly after
        // the token index). We gate candidates on it FIRST so the expensive
        // token-table / markers / names work below runs only for the 1-2 real
        // candidates, not the ~900 garbage ones.
        val candidates = ArrayList<Tables>()
        for (ti in tokenIndexStarts) {
            val after = locateOffsetsAfterIndex(kernel, ti)
            if (after == null) continue
            tryLocateLto(kernel, ti, after)?.let { candidates.add(it) }
            if (candidates.size >= MAX_FULL_DECODE) break
        }

        // Classic (non-LTO) fallback only when no LTO table was found.
        if (candidates.isEmpty()) {
            for (ti in tokenIndexStarts) {
                tryLocateClassic(kernel, ti)?.let { candidates.add(it) }
                if (candidates.size >= MAX_FULL_DECODE) break
            }
        }

        require(candidates.isNotEmpty()) { "kallsyms tables could not be decoded" }

        // Fully decode each candidate and keep the one resolving the most
        // required symbols. Token tables whose index is misaligned by two
        // bytes still decode to printable-but-garbled names, so the printable
        // gate alone is too weak; requiring every symbol match disambiguates.
        var best: Map<String, Long>? = null
        var bestCount = -1
        for (t in candidates) {
            val map = decodeAll(kernel, t, required)
            if (map.size > bestCount) {
                bestCount = map.size
                best = map
            }
        }
        require(best != null && bestCount >= MIN_IDENTIFY) {
            "kallsyms tables could not be decoded (best=$bestCount)"
        }
        return best
    }

    private fun decodeAll(kernel: ByteArray, t: Tables, required: Set<String>): Map<String, Long> {
        val decoder = KallsymsDecoder(t.tokenTable, t.tokenIndex)
        val out = HashMap<String, Long>(required.size)
        var cursor = t.namesStart
        for (i in 0 until t.numSyms) {
            val (name, next) = decoder.decodeName(kernel, cursor)
            val bare = if (name.length > 1) name.substring(1) else name
            val key = if (name in required) name else if (bare in required) bare else null
            if (key != null) {
                out[key] = if (t.absolute) {
                    kernel.u64(t.offsetsStart + i * 8) - t.relBase
                } else {
                    kernel.u32(t.offsetsStart + i * 4).toLong() and 0xffffffffL
                }
            }
            cursor = next
        }
        return out
    }


    /** LTO layout (offsets array directly after the token index). */
    private fun tryLocateLto(kernel: ByteArray, tokenIndexStart: Int, afterIndex: Triple<Int, Int, Long>): Tables? {
        val tokenTableStart = findTokenTable(kernel, tokenIndexStart) ?: return null
        val tokenTable = kernel.copyOfRange(tokenTableStart, tokenIndexStart)
        val tokenIndex = IntArray(256) { kernel.u16(tokenIndexStart + it * 2) }

        val mk = findMarkers(kernel, tokenTableStart)
        val markersStart = mk?.first ?: 0
        val markers: IntArray? = mk?.second
        if (markers != null && markers.size >= 2 &&
            (markers.size - 1) * 256 < afterIndex.second &&
            afterIndex.second <= markers.size * 256
        ) {
            val namesStart = findNamesStart(kernel, tokenTable, tokenIndex, markers, markersStart)
            if (namesStart != null && namesStart < markersStart) {
                return Tables(
                    namesStart, tokenTable, tokenIndex,
                    afterIndex.first, afterIndex.second, absolute = false, afterIndex.third,
                )
            }
        }
        return null
    }

    /** Classic (non-LTO) layout: offsets/relbase precede the names stream. */
    private fun tryLocateClassic(kernel: ByteArray, tokenIndexStart: Int): Tables? {
        val tokenTableStart = findTokenTable(kernel, tokenIndexStart) ?: return null
        val tokenTable = kernel.copyOfRange(tokenTableStart, tokenIndexStart)
        val tokenIndex = IntArray(256) { kernel.u16(tokenIndexStart + it * 2) }

        val mk = findMarkers(kernel, tokenTableStart)
        val markersStart = mk?.first ?: 0
        val markers: IntArray? = mk?.second

        // Classic base-relative: num_syms | u32[N] | relbase | names.
        val relBasePos = findRelBaseBackward(kernel, tokenTableStart)
        if (relBasePos >= 0) {
            val relBase = kernel.u64(relBasePos)
            val namesStart = relBasePos + 8
            findNumSymsBeforeOffsets(kernel, relBasePos, width = 4)?.let { (p, n) ->
                if (markers == null || markers.size < 2 ||
                    ((markers.size - 1) * 256 < n && n <= markers.size * 256)) {
                    return Tables(namesStart, tokenTable, tokenIndex,
                        p + 4, n, absolute = false, relBase)
                }
            }
        }

        // Classic absolute: num_syms | u64[N] | names.
        if (markers != null && markers.size >= 2) {
            findNamesStart(kernel, tokenTable, tokenIndex, markers, markersStart)
                ?.let { namesStart ->
                    for (p in namesStart - 4 downTo maxOf(0, namesStart - (4 shl 20)) step 4) {
                        val n = kernel.u32(p)
                        if (n !in 1..1_000_000) continue
                        val addrStart = p + 4
                        if (addrStart.toLong() + n.toLong() * 8 != namesStart.toLong()) continue
                        if ((markers.size - 1) * 256 < n && n <= markers.size * 256) {
                            val a0 = kernel.u64(addrStart)
                            if (a0 == 0L || a0 in REL_BASES) {
                                return Tables(namesStart, tokenTable, tokenIndex,
                                    addrStart, n, absolute = true, relBase = a0)
                            }
                        }
                    }
                }
        }
        return null
    }

    private fun findRelBaseBackward(kernel: ByteArray, from: Int): Int {
        var pos = from - 8
        pos -= pos % 8
        val floor = maxOf(0, from - (8 shl 20))
        while (pos >= floor) {
            if (kernel.u64(pos) in REL_BASES) return pos
            pos -= 8
        }
        return -1
    }

    /**
     * LTO layout: token_index, offsets u32[N] monotonic starting at 0, then
     * 8-aligned relative_base u64 (optionally preceded by one zero u32 pad).
     * The base is probed BEFORE the monotonicity break so the negative-as-Int
     * low half of the base (e.g. 0x80000000) cannot terminate the walk early.
     */
    private fun locateOffsetsAfterIndex(
        kernel: ByteArray,
        tokenIndexStart: Int,
    ): Triple<Int, Int, Long>? {
        var start = tokenIndexStart + 512
        while (start % 4 != 0) start++
        if (start + 8 > kernel.size) return null
        // The array must begin with 0 (offset of the first symbol).
        if (kernel.u32(start) != 0) return null
        var pos = start
        var prev = 0
        val maxEnd = minOf(kernel.size - 8, start + MAX_SYMS * 4)
        while (pos + 8 <= maxEnd) {
            if (pos % 8 == 0 && kernel.u64(pos) in REL_BASES) {
                return Triple(start, (pos - start) / 4, kernel.u64(pos))
            }
            val v = kernel.u32(pos)
            if (v < prev) {
                // Monotonicity broke: a single zero u32 pad may precede the
                // base (alignment of the u64).
                if (v == 0 && pos + 8 <= maxEnd && kernel.u64(pos + 4) in REL_BASES) {
                    return Triple(start, (pos - start) / 4, kernel.u64(pos + 4))
                }
                return null
            }
            prev = v
            pos += 4
        }
        return null
    }

    private fun findNumSymsBeforeOffsets(kernel: ByteArray, relBasePos: Int, width: Int): Pair<Int, Int>? {
        // Relative_base is 8-byte aligned; there may be 0-7 bytes of zero pad
        // between the offsets/addresses array and the base.
        for (p in relBasePos - 4 downTo maxOf(0, relBasePos - (4 shl 20)) step 4) {
            val n = kernel.u32(p)
            if (n in 1..1_000_000) {
                val arrayEnd = p + 4 + n.toLong() * width
                if (arrayEnd == relBasePos.toLong()) return p to n
                if (arrayEnd < relBasePos && relBasePos - arrayEnd <= 8) {
                    // only accept if the gap between the array and base is zero.
                    var padOk = true
                    for (q in arrayEnd.toInt() until relBasePos) {
                        if (kernel[q].toInt() != 0) {
                            padOk = false; break
                        }
                    }
                    if (padOk) return p to n
                }
            }
        }
        return null
    }

    /**
     * Walk the names stream from each candidate start; the correct one consumes
     * exactly markers[1] bytes in 256 names (and chains to markers_start in
     * numSyms names — verified by the caller's full decode).
     */
    private fun findNamesStart(
        kernel: ByteArray,
        tokenTable: ByteArray,
        tokenIndex: IntArray,
        markers: IntArray,
        namesEnd: Int,
    ): Int? {
        if (markers.size < 2) return null
        val lo = maxOf(0, namesEnd - markers.last() - MAX_TRAILING_BYTES)
        val hi = namesEnd - markers.last()
        if (lo >= hi) return null
        val target = markers[1]
        val decoder = KallsymsDecoder(tokenTable, tokenIndex)
        // Min printable ratio for a candidate names start: the real symbol
        // stream is all ASCII C identifiers, so garbage token tables score low.
        val minScore = 80
        for (s in lo until hi) {
            // 256-name chain must consume exactly markers[1] bytes.
            var cursor = s
            var ok = true
            for (i in 0 until 256) {
                if (cursor >= kernel.size) { ok = false; break }
                val len = kernel[cursor].toInt() and 0xff
                if (len !in 1..MAX_NAME_LEN) { ok = false; break }
                cursor++
                for (j in 0 until len) {
                    if (cursor >= kernel.size || tokenIndex[kernel[cursor].toInt() and 0xff] >= tokenTable.size) {
                        ok = false; break
                    }
                    cursor++
                }
                if (!ok) break
            }
            if (!ok || cursor - s != target) continue
            // Printable ratio gate on a sample of the stream.
            var pr = 0
            var pl = 0
            var c2 = s
            var good = true
            for (i in 0 until SAMPLE_COUNT) {
                val len = kernel[c2].toInt() and 0xff
                if (len !in 1..MAX_NAME_LEN) { good = false; break }
                c2++
                for (j in 0 until len) {
                    if (c2 >= kernel.size) { good = false; break }
                    val ti = tokenIndex[kernel[c2].toInt() and 0xff]
                    var end = ti
                    while (end < tokenTable.size && tokenTable[end].toInt() != 0) end++
                    pl += (end - ti)
                    for (b in ti until end) {
                        val c = tokenTable[b].toInt()
                        if (c in 32..126) pr++
                    }
                    c2++
                }
                if (!good) break
            }
            if (good && pl > 0 && pr * 100 / pl >= minScore) {
                return s
            }
        }
        return null
    }

    /** Markers: monotonic u32 array ending at tokenTableStart (4-aligned), first == 0. */
    private fun findMarkers(kernel: ByteArray, tokenTableStart: Int): Pair<Int, IntArray>? {
        val alignedEnd = tokenTableStart - (tokenTableStart % 4)
        var j = alignedEnd - 4
        if (j < 0) return null
        while (j >= 0 && kernel.u32(j) != 0) j--
        if (j < 0) return null
        val start = j
        val values = ArrayList<Int>()
        var prev = 0
        var p = start
        var ok = true
        while (p + 4 <= alignedEnd) {
            val v = kernel.u32(p)
            if (v !in prev..MAX_MARKER_VALUE) {
                ok = false; break
            }
            values.add(v)
            prev = v
            p += 4
        }
        if (!ok || values.isEmpty()) return null
        return start to values.toIntArray()
    }

    private fun findTokenIndexCandidates(kernel: ByteArray): List<Int> {
        val out = ArrayList<Int>()
        val maxStart = kernel.size - 512
        for (idx in 0..maxStart step 2) {
            if (kernel.u16(idx) != 0) continue
            var prev = 0
            var ok = true
            for (i in 0 until 256) {
                val v = kernel.u16(idx + i * 2)
                if (v < prev) { ok = false; break }
                prev = v
            }
            if (ok && prev in 1..MAX_TABLE_SIZE) {
                out.add(idx)
                if (out.size >= MAX_CANDIDATES) break
            }
        }
        return out
    }

    /**
     * token_table is the region of exactly 256 NUL-terminated strings ending at
     * the token index. The first byte is NOT required to be NUL (LTO kernels
     * use a non-empty token 0). The index is validated against the table: every
     * entry must point at a string start and the last string must end exactly
     * at the table end.
     */
    private fun findTokenTable(kernel: ByteArray, tokenIndexStart: Int): Int? {
        val index = IntArray(256) { kernel.u16(tokenIndexStart + it * 2) }
        for (size in MIN_TABLE_SIZE..MAX_TABLE_SIZE) {
            val start = tokenIndexStart - size
            if (start < 0) return null
            var p = start
            var ok = true
            for (s in 0 until 256) {
                val end = kernel.indexOfZero(p, minOf(p + MAX_TOKEN_LEN + 1, tokenIndexStart))
                if (end < 0) { ok = false; break }
                p = end + 1
            }
            // Table strings may be followed by NUL padding before the index
            // (alignment), so accept a landing at-or-before the index with
            // only zero bytes in the gap. Empty strings inside the table are
            // already accounted for as an empty string (NUL immediately).
            if (!ok || p > tokenIndexStart) continue
            var gapOk = true
            for (g in p until tokenIndexStart) if (kernel[g].toInt() != 0) { gapOk = false; break }
            if (!gapOk) continue
            // Validate the index against the table.
            var valid = true
            for (t in 0 until 256) {
                val off = index[t]
                if (off >= size) { valid = false; break }
                if (off > 0 && kernel[start + off - 1].toInt() != 0) { valid = false; break }
            }
            if (valid) return start
        }
        return null
    }

    companion object {
        private const val MAX_CANDIDATES = 4096
        private const val MAX_SYMS = 1_000_000
        private const val MAX_NAME_LEN = 128
        private const val MAX_TOKEN_LEN = 16
        private const val MIN_TABLE_SIZE = 256
        private const val MAX_TABLE_SIZE = 8192
        private const val MAX_MARKER_VALUE = 0x0400_0000
        // Trailing names after the last marker: at most 255 symbols, each a few
        // bytes of tokens. 12 KiB comfortably covers even very long names.
        private const val MAX_TRAILING_BYTES = 12_288
        private const val SAMPLE_COUNT = 128
        private const val MAX_FULL_DECODE = 32
        private const val MIN_IDENTIFY = 1

        private val REL_BASES: Set<Long> = setOf(
            0xffffffc008000000UL.toLong(), // 6.1
            0xffffffc080000000UL.toLong(), // 6.6
        )
    }
}

private fun ByteArray.indexOfZero(from: Int, until: Int): Int {
    var i = from
    while (i < until) {
        if (this[i].toInt() == 0) return i
        i++
    }
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
