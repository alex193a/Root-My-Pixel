package com.alex193a.rootmypixel.core.kallsyms

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Resolves symbol offsets from a decompressed Linux ARM64 kernel `Image`.
 *
 * Two kallsyms layouts are supported:
 *
 *  (A) base-relative (CONFIG_KALLSYMS_BASE_RELATIVE=y):
 *      num_syms(u32) | offsets(u32[N]) | relative_base(u64) | names
 *      offsets[i] is a delta from relative_base (= _text).
 *
 *  (B) absolute (CONFIG_KALLSYMS_BASE_RELATIVE=n):
 *      num_syms(u32) | addresses(u64[N]) | names
 *
 * After the names stream come markers, token_table and token_index; we anchor
 * on the token index (256 monotonic u16 entries) and token table (256
 * NUL-terminated strings) to locate the tables, then derive num_syms/names from
 * the layout. Candidates are scored by decoding a sample of names and keeping
 * the highest printable ratio. The scan is O(image size) and fails fast.
 */
class KallsymsScanner {

    private class Candidate(
        val namesStart: Int,
        val numSyms: Int,
        val tokenTable: ByteArray,
        val tokenIndex: IntArray,
        val absolute: Boolean,
        val offsetsStart: Int,
        val relBase: Long,
        val score: Int,
    )

    fun resolve(kernel: ByteArray, required: Set<String>): Map<String, Long> {
        val tokenIndexStarts = findTokenIndexCandidates(kernel)
        require(tokenIndexStarts.isNotEmpty()) { "kallsyms token index not found" }

        var best: Candidate? = null
        var bestScore = -1
        for (ti in tokenIndexStarts) {
            val cand = tryParse(kernel, ti) ?: continue
            if (cand.score > bestScore) {
                bestScore = cand.score
                best = cand
            }
        }
        require(best != null && bestScore >= MIN_SCORE) {
            "kallsyms tables could not be decoded (best score=$bestScore)"
        }
        val c = best

        val decoder = KallsymsDecoder(c.tokenTable, c.tokenIndex)
        val out = HashMap<String, Long>(required.size)
        var cursor = c.namesStart
        for (i in 0 until c.numSyms) {
            val (name, next) = decoder.decodeName(kernel, cursor)
            if (name in required) {
                out[name] = if (c.absolute) {
                    kernel.u64(c.offsetsStart + i * 8) - c.relBase
                } else {
                    kernel.u32(c.offsetsStart + i * 4).toLong() and 0xffffffffL
                }
            }
            cursor = next
        }
        return out
    }

    private fun tryParse(kernel: ByteArray, tokenIndexStart: Int): Candidate? {
        val tokenTableStart = findTokenTable(kernel, tokenIndexStart) ?: return null
        val tokenTable = kernel.copyOfRange(tokenTableStart, tokenIndexStart)
        val tokenIndex = IntArray(256) { kernel.u16(tokenIndexStart + it * 2) }
        val decoder = KallsymsDecoder(tokenTable, tokenIndex)

        // Try base-relative first: relative_base is a known link constant.
        val relBaseCandidates = longArrayOf(
            0xffffffc008000000UL.toLong(), // 6.1
            0xffffffc080000000UL.toLong(), // 6.6
        )
        val relBasePos = findU64Backward(kernel, tokenTableStart, relBaseCandidates)
        if (relBasePos >= 0) {
            val p = findNumSymsField(kernel, relBasePos, 4) ?: return null
            val numSyms = kernel.u32(p)
            if (numSyms !in 1..1_000_000) return null
            val namesStart = relBasePos + 8
            if (namesStart >= tokenTableStart) return null
            val score = scoreNames(kernel, decoder, namesStart, numSyms)
            if (score < 0) return null
            return Candidate(namesStart, numSyms, tokenTable, tokenIndex, absolute = false,
                offsetsStart = p + 4, relBase = kernel.u64(relBasePos), score = score)
        }

        // Absolute layout: num_syms | addresses(u64[N]) | names. The names end
        // where markers begin, right before the token table.
        return findAbsolute(kernel, tokenTableStart, tokenTable, tokenIndex, decoder)
    }

    private fun findAbsolute(
        kernel: ByteArray,
        tokenTableStart: Int,
        tokenTable: ByteArray,
        tokenIndex: IntArray,
        decoder: KallsymsDecoder,
    ): Candidate? {
        val markersStart = findMarkers(kernel, tokenTableStart) ?: return null
        val namesEnd = markersStart
        for (p in namesEnd - 4 downTo maxOf(0, namesEnd - (16 shl 20)) step 4) {
            val n = kernel.u32(p)
            if (n !in 1..1_000_000) continue
            val addrStart = p + 4
            val namesStart = addrStart + n * 8
            if (namesStart > namesEnd || namesStart < addrStart) continue
            val score = scoreNames(kernel, decoder, namesStart, n)
            if (score >= MIN_SCORE) {
                val relBase = 0xffffffc080000000UL.toLong()
                return Candidate(namesStart, n, tokenTable, tokenIndex, absolute = true,
                    offsetsStart = addrStart, relBase = relBase, score = score)
            }
        }
        return null
    }

    private fun findNumSymsField(kernel: ByteArray, relBasePos: Int, width: Int): Int? {
        for (p in relBasePos - 4 downTo maxOf(0, relBasePos - (16 shl 20)) step 4) {
            val n = kernel.u32(p)
            if (n in 1..1_000_000 && p + 4 + n.toLong() * width == relBasePos.toLong()) {
                return p
            }
        }
        return null
    }

    private fun findU64Backward(kernel: ByteArray, from: Int, values: LongArray): Int {
        // relative_base is an 8-byte aligned u64; align the scan start so every
        // 8-aligned offset is visited, not a single congruence class.
        var pos = from - 8
        pos -= pos % 8
        val floor = maxOf(0, from - (16 shl 20))
        while (pos >= floor) {
            if (kernel.u64(pos) in values) return pos
            pos -= 8
        }
        return -1
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
            if (ok && prev in 1..4095) {
                out.add(idx)
                if (out.size >= MAX_CANDIDATES) break
            }
        }
        return out
    }

    private fun findTokenTable(kernel: ByteArray, tokenIndexStart: Int): Int? {
        for (size in 256..4096) {
            val start = tokenIndexStart - size
            if (start < 0) return null
            if (kernel[start].toInt() != 0) continue
            var p = start
            var ok = true
            for (s in 0 until 256) {
                val end = kernel.indexOfZero(p, tokenIndexStart)
                if (end < 0 || end - p > 64) { ok = false; break }
                p = end + 1
            }
            if (ok && p == tokenIndexStart) return start
        }
        return null
    }

    private fun findMarkers(kernel: ByteArray, tokenTableStart: Int): Int? {
        val alignedEnd = tokenTableStart - (tokenTableStart % 4)
        for (start in alignedEnd - 4 downTo maxOf(0, alignedEnd - 8192) step 4) {
            if (kernel.u32(start) != 0) continue
            var prev = 0
            var ok = true
            var j = start
            while (j + 4 <= alignedEnd) {
                val v = kernel.u32(j)
                if (v < prev) { ok = false; break }
                prev = v
                j += 4
            }
            if (ok) return start
        }
        return null
    }

    private fun scoreNames(
        kernel: ByteArray,
        decoder: KallsymsDecoder,
        namesStart: Int,
        count: Int,
    ): Int {
        var cursor = namesStart
        var printable = 0
        var total = 0
        var sampled = 0
        val limit = minOf(count, SAMPLE_COUNT)
        while (sampled < limit) {
            val (name, next) = runCatching { decoder.decodeName(kernel, cursor) }.getOrElse { return -1 }
            if (name.isNotEmpty()) {
                total += name.length
                printable += name.count { it in ' '..'~' }
            }
            cursor = next
            sampled++
        }
        if (total == 0) return -1
        return printable * 100 / total
    }

    companion object {
        private const val MAX_CANDIDATES = 8
        private const val SAMPLE_COUNT = 128
        private const val MIN_SCORE = 60
    }
}

private fun ByteArray.indexOfZero(from: Int, until: Int): Int {
    for (i in from until until) if (this[i].toInt() == 0) return i
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
