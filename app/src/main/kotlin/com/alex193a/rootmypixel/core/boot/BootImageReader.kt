package com.alex193a.rootmypixel.core.boot

import android.content.ContentResolver
import android.net.Uri
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.zip.GZIPInputStream
import java.util.zip.ZipInputStream

/** Reads Pixel boot images without loading a factory archive into memory. */
class BootImageReader(private val resolver: ContentResolver) {

    fun readKernel(uri: Uri, onProgress: (String) -> Unit = {}): ByteArray {
        onProgress("Reading boot image…")
        val stream = resolver.openInputStream(uri)
            ?: throw IOException("Unable to open selected image")
        stream.use { input ->
            val buffered = input.buffered()
            val head = ByteArray(4)
            var read = 0
            while (read < head.size) {
                val n = buffered.read(head, read, head.size - read)
                if (n < 0) break
                read += n
            }
            val boot = if (read == 4 && head.zipMagic) {
                extractBootFromZip(prefix(buffered, head), onProgress)
            } else {
                prefix(buffered, head, read).readBytesBounded(MAX_BOOT_BYTES)
            }
            return KernelDecompressor.decompress(parseBootImage(boot), onProgress)
        }
    }

    private fun prefix(buffered: InputStream, head: ByteArray, headLen: Int = head.size): InputStream =
        object : InputStream() {
            private var pos = 0
            override fun read(): Int {
                if (pos < headLen) return head[pos++].toInt() and 0xff
                return buffered.read()
            }

            override fun read(b: ByteArray, off: Int, len: Int): Int {
                if (len == 0) return 0
                var done = 0
                if (pos < headLen) {
                    val n = minOf(len, headLen - pos)
                    head.copyInto(b, off, pos, pos + n)
                    pos += n
                    done = n
                }
                if (done < len) {
                    val more = buffered.read(b, off + done, len - done)
                    if (more < 0) return if (done > 0) done else -1
                    done += more
                }
                return done
            }
        }

    private fun extractBootFromZip(input: InputStream, onProgress: (String) -> Unit): ByteArray {
        ZipInputStream(input).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                val entryName = entry.name.substringAfterLast('/').lowercase()
                if (!entry.isDirectory && entryName == "boot.img") {
                    onProgress("Extracting boot.img from factory image…")
                    return zip.readBytesBounded(MAX_BOOT_BYTES)
                }
            }
        }
        throw IOException("Factory image does not contain boot.img")
    }

    companion object {
        private const val MAX_BOOT_BYTES = 128L * 1024 * 1024
        private const val BOOT_MAGIC = "ANDROID!"

        private val ByteArray.zipMagic: Boolean
            get() = size >= 4 && this[0] == 'P'.code.toByte() && this[1] == 'K'.code.toByte() &&
                (this[2].toInt() and 0xff) == 0x03 && (this[3].toInt() and 0xff) == 0x04

        internal fun parseBootImage(image: ByteArray): ByteArray {
            require(image.size >= 4096) { "Boot image is truncated" }
            require(image.copyOfRange(0, 8).decodeToString() == BOOT_MAGIC) {
                "Invalid Android boot image magic"
            }
            val kernelSize = image.le32(8).toLong()
            require(kernelSize in 1..MAX_BOOT_BYTES) { "Invalid kernel size: $kernelSize" }
            val headerVersion = image.le32(40)
            val kernelOffset = if (headerVersion >= 3) {
                // v3/v4 store header_size at 36; fall back to 4096 when zero.
                val headerSize = image.le32(36)
                if (headerSize in 512..65536) headerSize else 4096
            } else {
                val pageSize = image.le32(36)
                require(pageSize in 512..65536 && Integer.bitCount(pageSize) == 1) {
                    "Invalid boot image page size: $pageSize"
                }
                pageSize
            }
            require(kernelOffset + kernelSize <= image.size) { "Kernel exceeds boot image" }
            return image.copyOfRange(kernelOffset, (kernelOffset + kernelSize).toInt())
        }
    }
}

internal object KernelDecompressor {
    private val GZIP = byteArrayOf(0x1f, 0x8b.toByte())
    private const val LZ4_FRAME_MAGIC = 0x184D2204
    private const val LZ4_LEGACY_MAGIC = 0x184C2102
    private const val ARM64_MAGIC_OFFSET = 0x38
    private const val ARM64_MAGIC = 0x644d5241

    fun decompress(kernel: ByteArray, onProgress: (String) -> Unit = {}): ByteArray {
        onProgress("Decompressing Kernel Image…")
        val result = when {
            kernel.size >= 2 && kernel[0] == GZIP[0] && kernel[1] == GZIP[1] ->
                GZIPInputStream(kernel.inputStream()).readBytesBounded(MAX_KERNEL_BYTES)
            kernel.size >= 4 && kernel.le32(0) == LZ4_FRAME_MAGIC -> Lz4Frame.decode(kernel)
            kernel.size >= 4 && kernel.le32(0) == LZ4_LEGACY_MAGIC -> Lz4Legacy.decode(kernel)
            else -> kernel
        }
        require(result.size > ARM64_MAGIC_OFFSET && result.le32(ARM64_MAGIC_OFFSET) == ARM64_MAGIC) {
            "Unsupported kernel format (expected ARM64 Image)"
        }
        return result
    }

    private const val MAX_KERNEL_BYTES = 256L * 1024 * 1024
}

private object Lz4Frame {
    fun decode(input: ByteArray): ByteArray {
        var p = 4
        require(p < input.size) { "Truncated LZ4 frame" }
        val flg = input[p++].toInt() and 0xff
        p++ // block descriptor byte (ignored for decoding)
        require((flg ushr 6) == 1) { "Unsupported LZ4 frame version" }
        val hasContentSize = flg and 0x08 != 0
        val hasDictId = flg and 0x01 != 0
        if (hasDictId) p += 4
        if (hasContentSize) p += 8
        p++ // header checksum (not verified)

        val out = ByteArrayOutputStream()
        while (p + 4 <= input.size) {
            val rawSize = input.le32(p)
            p += 4
            if (rawSize == 0) break // end mark
            val uncompressed = rawSize and Int.MAX_VALUE
            require(p + uncompressed <= input.size) { "Truncated LZ4 block" }
            val block = input.copyOfRange(p, p + uncompressed)
            p += uncompressed
            if (rawSize < 0) {
                out.write(block)
            } else {
                out.write(decodeBlock(block))
            }
            if (flg and 0x10 != 0) p += 4 // block checksum (not verified)
        }
        return out.toByteArray()
    }

    private fun decodeBlock(src: ByteArray): ByteArray = lz4DecodeBlock(src)
}

private object Lz4Legacy {
    // Pixel boot images ship kernels compressed with the legacy LZ4 format:
    //   magic u32 (0x184C2102), then blocks. Each block is a u32 compressed
    //   size; the high bit marks an uncompressed block. A zero size ends.
    fun decode(input: ByteArray): ByteArray {
        var p = 4
        val out = ByteArrayOutputStream()
        while (p + 4 <= input.size) {
            val rawSize = input.le32(p)
            p += 4
            if (rawSize == 0) break
            val uncompressed = rawSize and Int.MAX_VALUE
            require(p + uncompressed <= input.size) { "Truncated LZ4 legacy block" }
            val block = input.copyOfRange(p, p + uncompressed)
            p += uncompressed
            if (rawSize < 0) out.write(block) else out.write(lz4DecodeBlock(block))
        }
        return out.toByteArray()
    }
}

// LZ4 block (sequence of literal runs + matches). Shared by frame and legacy.
private fun lz4DecodeBlock(src: ByteArray): ByteArray {
    var buf = ByteArray(maxOf(1024, src.size * 2))
    var size = 0
    fun ensure(capacity: Int) {
        if (capacity > buf.size) buf = buf.copyOf(maxOf(capacity, buf.size * 2))
    }
    var p = 0
    while (p < src.size) {
        val token = src[p++].toInt() and 0xff
        var literal = token ushr 4
        if (literal == 15) {
            var n: Int
            do {
                n = src[p++].toInt() and 0xff
                literal += n
            } while (n == 255)
        }
        require(p + literal <= src.size) { "Truncated LZ4 literal" }
        ensure(size + literal)
        src.copyInto(buf, size, p, p + literal)
        size += literal
        p += literal
        if (p == src.size) break
        require(p + 2 <= src.size) { "Truncated LZ4 match" }
        val offset = (src[p].toInt() and 0xff) or ((src[p + 1].toInt() and 0xff) shl 8)
        p += 2
        require(offset in 1..size) { "Invalid LZ4 match offset" }
        var match = token and 0x0f
        if (match == 15) {
            var n: Int
            do {
                n = src[p++].toInt() and 0xff
                match += n
            } while (n == 255)
        }
        match += 4
        ensure(size + match)
        var copyFrom = size - offset
        repeat(match) {
            buf[size++] = buf[copyFrom++]
            if (copyFrom == size - 1) copyFrom = size - 1 - offset
        }
    }
    return buf.copyOf(size)
}

private fun InputStream.readBytesBounded(max: Long): ByteArray {
    val out = ByteArrayOutputStream()
    val buffer = ByteArray(64 * 1024)
    var total = 0L
    while (true) {
        val n = read(buffer)
        if (n < 0) break
        total += n
        require(total <= max) { "Input exceeds safety limit" }
        out.write(buffer, 0, n)
    }
    return out.toByteArray()
}

private fun ByteArray.le32(offset: Int): Int =
    (this[offset].toInt() and 255) or ((this[offset + 1].toInt() and 255) shl 8) or
        ((this[offset + 2].toInt() and 255) shl 16) or ((this[offset + 3].toInt() and 255) shl 24)
