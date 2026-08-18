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
        resolver.openInputStream(uri)?.use { input ->
            val name = uri.lastPathSegment.orEmpty().lowercase()
            val boot = if (name.endsWith(".zip")) extractBootFromZip(input, onProgress)
            else input.readBytesBounded(MAX_BOOT_BYTES)
            return KernelDecompressor.decompress(parseBootImage(boot), onProgress)
        } ?: throw IOException("Unable to open selected image")
    }

    private fun extractBootFromZip(input: InputStream, onProgress: (String) -> Unit): ByteArray {
        ZipInputStream(input.buffered()).use { zip ->
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
        private const val PAGE_SIZE = 4096

        internal fun parseBootImage(image: ByteArray): ByteArray {
            require(image.size >= PAGE_SIZE) { "Boot image is truncated" }
            require(image.copyOfRange(0, 8).decodeToString() == BOOT_MAGIC) {
                "Invalid Android boot image magic"
            }
            val kernelSize = image.le32(8).toLong()
            require(kernelSize in 1..MAX_BOOT_BYTES) { "Invalid kernel size: $kernelSize" }
            val headerVersion = image.le32(40)
            val kernelOffset = if (headerVersion >= 3) PAGE_SIZE else {
                val pageSize = image.le32(36)
                require(pageSize in 512..65536 && Integer.bitCount(pageSize) == 1)
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
    private const val ARM64_MAGIC_OFFSET = 0x38
    private const val ARM64_MAGIC = 0x644d5241

    fun decompress(kernel: ByteArray, onProgress: (String) -> Unit = {}): ByteArray {
        onProgress("Decompressing Kernel Image…")
        val result = when {
            kernel.startsWith(GZIP) -> GZIPInputStream(kernel.inputStream()).readBytesBounded(MAX_KERNEL_BYTES)
            kernel.size >= 4 && kernel.le32(0) == LZ4_FRAME_MAGIC -> Lz4Frame.decode(kernel)
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
        val bd = input[p++].toInt() and 0xff
        require((flg ushr 6) == 1) { "Unsupported LZ4 frame version" }
        val hasContentSize = flg and 0x08 != 0
        if (hasContentSize) p += 8
        if (flg and 0x01 != 0) p++ // dictionary id
        p++ // header checksum
        val out = ByteArrayOutputStream()
        while (p + 4 <= input.size) {
            val rawSize = input.le32(p); p += 4
            if (rawSize == 0) break
            val uncompressed = rawSize and Int.MAX_VALUE
            require(uncompressed <= input.size - p) { "Truncated LZ4 block" }
            val block = input.copyOfRange(p, p + uncompressed); p += uncompressed
            if (rawSize < 0) out.write(block) else out.write(decodeBlock(block))
        }
        return out.toByteArray()
    }

    private fun decodeBlock(src: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(src.size * 2)
        var p = 0
        while (p < src.size) {
            val token = src[p++].toInt() and 0xff
            var literal = token ushr 4
            if (literal == 15) { var n: Int; do { n = src[p++].toInt() and 0xff; literal += n } while (n == 255) }
            require(p + literal <= src.size); out.write(src, p, literal); p += literal
            if (p == src.size) break
            require(p + 2 <= src.size)
            val offset = (src[p].toInt() and 0xff) or ((src[p + 1].toInt() and 0xff) shl 8); p += 2
            require(offset > 0 && offset <= out.size())
            var match = token and 0x0f
            if (match == 15) { var n: Int; do { n = src[p++].toInt() and 0xff; match += n } while (n == 255) }
            match += 4
            repeat(match) { val bytes = out.toByteArray(); out.write(bytes[bytes.size - offset].toInt()) }
        }
        return out.toByteArray()
    }
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

private fun ByteArray.startsWith(prefix: ByteArray): Boolean = size >= prefix.size && prefix.indices.all { this[it] == prefix[it] }
private fun ByteArray.le32(offset: Int): Int = (this[offset].toInt() and 255) or ((this[offset + 1].toInt() and 255) shl 8) or ((this[offset + 2].toInt() and 255) shl 16) or ((this[offset + 3].toInt() and 255) shl 24)
