package com.alex193a.rootmypixel.core.kallsyms

import com.alex193a.rootmypixel.core.boot.BootImageReader
import com.alex193a.rootmypixel.core.boot.KernelDecompressor
import com.alex193a.rootmypixel.domain.model.TargetConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.zip.GZIPOutputStream

class KallsymsTest {

    // Builds a canonical kallsyms blob (num_syms, offsets, relative_base, names,
    // markers, token_table, token_index) as scripts/kallsyms.c emits it.
    private fun buildSyntheticKernel(): ByteArray {
        val base = 0xffffffc008000000UL.toLong()
        val symbols = linkedMapOf(
            "init_task" to 0x100L,
            "selinux_enforcing" to 0x200L,
            "kmalloc_caches" to 0x300L,
        )
        // Token table: token 0 is the empty string (single NUL); tokens 1..255
        // are one printable char each. This matches real kallsyms: token_index[0]
        // points at an empty string.
        val tokenTable = ByteArrayOutputStream()
        tokenTable.write(0) // token 0: empty
        for (t in 1 until 256) {
            tokenTable.write(32 + (t % 95))
            tokenTable.write(0)
        }
        val tokenTableBytes = tokenTable.toByteArray()
        val tokenIndex = IntArray(256) { if (it == 0) 0 else it * 2 - 1 }

        fun encodeName(name: String): ByteArray {
            val out = ByteArrayOutputStream()
            out.write(name.length)
            for (c in name) out.write((c.code - 32).toInt())
            return out.toByteArray()
        }

        val names = ByteArrayOutputStream()
        for (name in symbols.keys) names.write(encodeName(name))
        val namesBytes = names.toByteArray()

        val out = ByteArrayOutputStream()
        // num_syms
        out.write(intLE(symbols.size))
        // offsets
        for (off in symbols.values) out.write(intLE(off.toInt()))
        // relative_base
        out.write(longLE(base))
        // names
        out.write(namesBytes)
        // markers (single zero for N < 256)
        out.write(intLE(0))
        // token_table
        out.write(tokenTableBytes)
        // token_index
        for (t in tokenIndex) out.write(shortLE(t))
        return out.toByteArray()
    }

    @Test
    fun scanner_resolvesRequiredSymbols() {
        val kernel = buildSyntheticKernel()
        val scanner = KallsymsScanner()
        val resolved = scanner.resolve(kernel, setOf("init_task", "selinux_enforcing", "kmalloc_caches"))
        assertEquals(3, resolved.size)
        assertEquals(0x100L, resolved["init_task"])
        assertEquals(0x200L, resolved["selinux_enforcing"])
        assertEquals(0x300L, resolved["kmalloc_caches"])
    }

    @Test
    fun symbolResolver_buildsValidConfig() {
        val config = SymbolResolver.toConfig(
            "6.1.157-android14-11",
            mapOf(
                "init_task" to (0xffffffc008000000UL.toLong() + 0x100),
                "root_task_group" to (0xffffffc008000000UL.toLong() + 0x200),
                "selinux_enforcing" to (0xffffffc008000000UL.toLong() + 0x300),
                "selinux_blob_sizes" to (0xffffffc008000000UL.toLong() + 0x400),
                "security_hook_heads" to (0xffffffc008000000UL.toLong() + 0x500),
                "kmalloc_caches" to (0xffffffc008000000UL.toLong() + 0x600),
                "anon_pipe_buf_ops" to (0xffffffc008000000UL.toLong() + 0x700),
                "call_usermodehelper_exec_work" to (0xffffffc008000000UL.toLong() + 0x800),
                "system_unbound_wq" to (0xffffffc008000000UL.toLong() + 0x900),
                "ashmem_ioctl" to (0xffffffc008000000UL.toLong() + 0xa00),
                "ashmem_mmap" to (0xffffffc008000000UL.toLong() + 0xb00),
                "ashmem_open" to (0xffffffc008000000UL.toLong() + 0xc00),
                "ashmem_release" to (0xffffffc008000000UL.toLong() + 0xd00),
                "ashmem_show_fdinfo" to (0xffffffc008000000UL.toLong() + 0xe00),
                "configfs_read_iter" to (0xffffffc008000000UL.toLong() + 0xf00),
                "configfs_bin_write_iter" to (0xffffffc008000000UL.toLong() + 0x1000),
                "copy_splice_read" to (0xffffffc008000000UL.toLong() + 0x1100),
                "noop_llseek" to (0xffffffc008000000UL.toLong() + 0x1200),
            ),
        )
        assertEquals(61, config.kernelFamily)
        assertEquals(4096, config.pageSize)
        assertEquals(0x100L, config.symbols["init_task"])
        val bin = config.toBinary()
        assertEquals(352, bin.size)
        val buf = ByteBuffer.wrap(bin).order(ByteOrder.LITTLE_ENDIAN)
        assertEquals(TargetConfig.MAGIC, buf.getInt(0))
        assertEquals(61, buf.getInt(8))
        assertEquals(4096, buf.getInt(12))
    }

    @Test
    fun bootHeader_v3_parsesKernel() {
        val image = ByteArray(4096 + 100)
        "ANDROID!".toByteArray().copyInto(image, 0)
        image[8] = 100 // kernel size low byte
        image[40] = 3 // header version v3
        for (i in 0 until 100) image[4096 + i] = 0x5a
        val kernel = BootImageReader.parseBootImage(image)
        assertEquals(100, kernel.size)
        assertEquals(0x5a.toByte(), kernel[0])
    }

    @Test
    fun legacyLz4_uncompressedBlock_decompresses() {
        val raw = ByteArray(0x40)
        byteArrayOf(0x41, 0x52, 0x4d, 0x64).copyInto(raw, 0x38) // "ARM\x64"
        val out = ByteArrayOutputStream()
        out.write(intLE(0x184C2102.toInt()))
        out.write(intLE(0x80000000.toInt() or raw.size)) // uncompressed block
        out.write(raw)
        out.write(intLE(0)) // end mark
        val decompressed = KernelDecompressor.decompress(out.toByteArray())
        assertEquals(raw[0x38], decompressed[0x38])
        assertTrue(decompressed.size >= 0x40)
    }

    @Test
    fun realBootImage_extractsArm64Kernel() {
        val path = "/Users/alex193a/Library/Application Support/PixelFlasher/" +
            "boot_images4/d81bbb49154d4f7203afcce33dee5867e8e6ba46/boot.img"
        val file = File(path)
        assumeTrue("reference boot.img not present on this machine", file.exists())
        val image = file.readBytes()
        val kernel = BootImageReader.parseBootImage(image)
        val decompressed = KernelDecompressor.decompress(kernel)
        // ARM64 Image header magic at offset 0x38.
        assertEquals(0x41, decompressed[0x38].toInt())
        assertEquals(0x52, decompressed[0x39].toInt())
        assertEquals(0x4d, decompressed[0x3a].toInt())
        assertEquals(0x64, decompressed[0x3b].toInt())
    }

    @Test
    fun realBootImage_kallsymsResolvesFrankelOffsets() {
        val path = "/Users/alex193a/Library/Application Support/PixelFlasher/" +
            "boot_images4/d81bbb49154d4f7203afcce33dee5867e8e6ba46/boot.img"
        val file = File(path)
        assumeTrue("reference boot.img not present on this machine", file.exists())
        val image = file.readBytes()
        val kernel = KernelDecompressor.decompress(BootImageReader.parseBootImage(image))
        val started = System.currentTimeMillis()
        val symbols = KallsymsScanner().resolve(kernel, SymbolResolver.requiredSymbols)
        val elapsed = System.currentTimeMillis() - started
        println("kallsyms resolved ${symbols.size} symbols in ${elapsed}ms")
        // 6.6 frankel reference offsets (must match the payload ground truth).
        assertEquals(0xc8d908L, symbols["ashmem_ioctl"])
        assertEquals(0xc8e018L, symbols["ashmem_mmap"])
        assertEquals(0xc8e238L, symbols["ashmem_open"])
        assertEquals(0xc8e2c0L, symbols["ashmem_release"])
        assertEquals(0xc8e34cL, symbols["ashmem_show_fdinfo"])
        assertEquals(0x491eecL, symbols["configfs_read_iter"])
        assertEquals(0x492418L, symbols["configfs_bin_write_iter"])
        assertEquals(0x415be0L, symbols["copy_splice_read"])
        assertEquals(0x3c8940L, symbols["noop_llseek"])
        assertEquals(0x212e280L, symbols["init_task"])
        assertEquals(0x2328980L, symbols["root_task_group"])
        assertEquals(0x16849b0L, symbols["selinux_blob_sizes"])
        assertEquals(0x1684278L, symbols["security_hook_heads"])
        assertEquals(0x1683db8L, symbols["kmalloc_caches"])
        assertEquals(0x1176748L, symbols["anon_pipe_buf_ops"])
        assertEquals(0x2122260L, symbols["nfulnl_logger"])
        assertEquals(0x238b2d8L, symbols["sysctl_bootid"])
        // selinux_enforcing is at offset 0 of selinux_state on 6.1/6.6.
        assertEquals(0x236a2e0L, symbols["selinux_state"])
        // The scan must stay well within the on-device time budget.
        assertTrue("took too long: ${elapsed}ms", elapsed < 15_000)
        // The assembled config must pass validation.
        val config = SymbolResolver.toConfig("6.6.118-android15-8", symbols)
        assertTrue(config.validate().isSuccess)
    }

    @Test
    fun gzipKernel_decompresses() {
        val raw = ByteArray(0x40)
        val magic = byteArrayOf(0x41, 0x52, 0x4d, 0x64) // "ARM\x64" LE == 0x644d5241
        magic.copyInto(raw, 0x38)
        val gz = ByteArrayOutputStream()
        GZIPOutputStream(gz).use { it.write(raw) }
        val decompressed = KernelDecompressor.decompress(gz.toByteArray())
        assertTrue(decompressed.size >= 0x40)
        assertEquals(raw[0x38], decompressed[0x38])
    }

    @Test
    fun decoder_roundTripsNames() {
        val tokenTable = ByteArrayOutputStream()
        tokenTable.write(0)
        for (t in 1 until 256) {
            tokenTable.write(32 + (t % 95))
            tokenTable.write(0)
        }
        val tokenIndex = IntArray(256) { if (it == 0) 0 else it * 2 - 1 }
        val names = ByteArrayOutputStream()
        names.write(9)
        for (c in "init_task") names.write(c.code - 32)
        val decoder = KallsymsDecoder(tokenTable.toByteArray(), tokenIndex)
        val (name, next) = decoder.decodeName(names.toByteArray(), 0)
        assertEquals("init_task", name)
        assertEquals(10, next)
    }

    private fun intLE(v: Int): ByteArray {
        val b = ByteBuffer.allocate(4).order(ByteOrder.LITTLE_ENDIAN)
        b.putInt(v)
        return b.array()
    }

    private fun shortLE(v: Int): ByteArray {
        val b = ByteBuffer.allocate(2).order(ByteOrder.LITTLE_ENDIAN)
        b.putShort(v.toShort())
        return b.array()
    }

    private fun longLE(v: Long): ByteArray {
        val b = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
        b.putLong(v)
        return b.array()
    }
}
