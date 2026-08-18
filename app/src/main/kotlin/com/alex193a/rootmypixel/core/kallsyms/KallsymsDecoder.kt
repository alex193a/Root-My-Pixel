package com.alex193a.rootmypixel.core.kallsyms

import java.nio.charset.StandardCharsets

/**
 * Decodes Linux kallsyms token-compressed symbol names.
 *
 * The token table is scanned once to precompute each token's (start, end)
 * range, so name decoding is O(symbol length) with no per-token search.
 */
class KallsymsDecoder(
    private val tokenTable: ByteArray,
    private val tokenIndex: IntArray,
) {
    private val tokenStart = IntArray(256)
    private val tokenEnd = IntArray(256)

    init {
        require(tokenIndex.size == 256 && tokenTable.isNotEmpty()) {
            "Invalid kallsyms token tables"
        }
        for (t in 0 until 256) {
            val start = tokenIndex[t]
            var end = start
            while (end < tokenTable.size && tokenTable[end].toInt() != 0) end++
            tokenStart[t] = start
            tokenEnd[t] = end
        }
    }

    /** Returns the decoded name and the offset of the next name. */
    fun decodeName(names: ByteArray, offset: Int): Pair<String, Int> {
        require(offset in names.indices) { "Invalid kallsyms name offset" }
        val length = names[offset].toInt() and 0xff
        var cursor = offset + 1
        val out = ByteArrayOutputStreamFast(length * 3)
        repeat(length) {
            require(cursor < names.size) { "Truncated kallsyms name" }
            val token = names[cursor++].toInt() and 0xff
            val start = tokenStart[token]
            val end = tokenEnd[token]
            out.write(tokenTable, start, end - start)
        }
        return out.toString(StandardCharsets.US_ASCII) to cursor
    }
}

private class ByteArrayOutputStreamFast(initialCapacity: Int) {
    private var buf = ByteArray(if (initialCapacity > 0) initialCapacity else 16)
    private var count = 0

    fun write(src: ByteArray, off: Int, len: Int) {
        val needed = count + len
        if (needed > buf.size) buf = buf.copyOf(maxOf(needed, buf.size * 2))
        src.copyInto(buf, count, off, off + len)
        count += len
    }

    fun toString(charset: java.nio.charset.Charset): String =
        String(buf, 0, count, charset)
}
