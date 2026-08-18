package com.alex193a.rootmypixel.core.kallsyms

import java.nio.charset.StandardCharsets

/** Decodes Linux kallsyms token-compressed symbol names. */
object KallsymsDecoder {
    fun decodeName(names: ByteArray, offset: Int, tokenTable: ByteArray, tokenIndex: IntArray): Pair<String, Int> {
        require(offset in names.indices) { "Invalid kallsyms name offset" }
        val length = names[offset].toInt() and 0xff
        var cursor = offset + 1
        val out = StringBuilder()
        repeat(length) {
            require(cursor < names.size) { "Truncated kallsyms name" }
            val token = names[cursor++].toInt() and 0xff
            val start = tokenIndex[token]
            require(start in tokenTable.indices) { "Invalid kallsyms token index" }
            var end = start
            while (end < tokenTable.size && tokenTable[end].toInt() != 0) end++
            out.append(String(tokenTable, start, end - start, StandardCharsets.US_ASCII))
        }
        return out.toString().removePrefix("\u0000") to cursor
    }

    fun decodeAll(names: ByteArray, symbolCount: Int, tokenTable: ByteArray, tokenIndex: IntArray): List<String> {
        val symbols = ArrayList<String>(symbolCount)
        var offset = 0
        repeat(symbolCount) {
            val (name, next) = decodeName(names, offset, tokenTable, tokenIndex)
            symbols += name
            offset = next
        }
        return symbols
    }
}
