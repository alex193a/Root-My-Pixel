package com.alex193a.rootmypixel.domain.model

import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * Runtime configuration shared with the generic native payload.
 *
 * The binary layout must stay in lockstep with `target_config_t` in
 * Root-My-Pixel-Payloads/src/target_config.h (packed struct: 16 bytes header +
 * 6 uint64 geometry + 4 uint32 knobs + 27 uint64 symbols + 14 uint32 layouts).
 */
data class TargetConfig(
    val kernelFamily: Int,
    val pageSize: Int,
    val kimageTextBase: Long,
    val p0PageOffset: Long,
    val p0PhysOffset: Long,
    val directMapBase: Long,
    val directMapEnd: Long,
    val vmemmapStart: Long,
    val mmStructSize: Int,
    val kmallocCgroupType: Int,
    val kmallocCacheTypes: Int,
    val kmallocPipeIndex: Int,
    val symbols: Map<String, Long>,
    val layouts: Map<String, Int>,
) {
    fun validate(): Result<Unit> {
        require(kernelFamily == 61 || kernelFamily == 66) { "Unsupported kernel family" }
        // The generic payloads are compiled for 4 KB pages. A 16 KB kernel needs
        // a separate payload; refuse before doing anything dangerous on-device.
        require(pageSize == 4096) { "Unsupported page size: $pageSize (generic payload is 4 KB only)" }
        require(mmStructSize in 1..0x4000) { "Invalid mm_struct size" }
        require(directMapEnd > directMapBase) { "Invalid direct map range" }
        require(kimageTextBase != 0L) { "KIMAGE_TEXT_BASE not resolved" }
        val required = listOf(
            "init_task", "root_task_group", "selinux_enforcing", "selinux_blob_sizes",
            "security_hook_heads", "kmalloc_caches", "anon_pipe_buf_ops",
            "call_usermodehelper_exec_work", "system_unbound_wq", "ashmem_ioctl",
            "ashmem_mmap", "ashmem_open", "ashmem_release", "ashmem_show_fdinfo",
            "ashmem_fops", "ashmem_misc_fops", "configfs_read_iter",
            "configfs_bin_write_iter", "copy_splice_read", "noop_llseek",
        )
        required.forEach {
            require((symbols[it] ?: 0L) != 0L) { "Required symbol not resolved: $it" }
        }
        return Result.success(Unit)
    }

    /** Packed wire format consumed by target_config.c. */
    fun toBinary(): ByteArray {
        val out = ByteBuffer.allocate(WIRE_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        out.putInt(MAGIC)
        out.putInt(VERSION)
        out.putInt(kernelFamily)
        out.putInt(pageSize)
        out.putLong(kimageTextBase)
        out.putLong(p0PageOffset)
        out.putLong(p0PhysOffset)
        out.putLong(directMapBase)
        out.putLong(directMapEnd)
        out.putLong(vmemmapStart)
        out.putInt(mmStructSize)
        out.putInt(kmallocCgroupType)
        out.putInt(kmallocCacheTypes)
        out.putInt(kmallocPipeIndex)
        SYMBOL_ORDER.forEach { out.putLong(symbols[it] ?: 0L) }
        LAYOUT_ORDER.forEach { out.putInt(layouts[it] ?: 0) }
        return out.array()
    }

    companion object {
        const val MAGIC = 0x50584c43
        const val VERSION = 1

        /** Must match CFG_SYM_* indices in target_config.h exactly. */
        val SYMBOL_ORDER = listOf(
            "ashmem_ioctl", "ashmem_mmap", "ashmem_open", "ashmem_release", "ashmem_show_fdinfo",
            "ashmem_misc_fops", "ashmem_fops", "ashmem_compat_ioctl", "configfs_read_iter",
            "configfs_bin_write_iter", "copy_splice_read", "noop_llseek", "init_task", "root_task_group",
            "selinux_enforcing", "selinux_blob_sizes", "security_hook_heads", "kmalloc_caches",
            "anon_pipe_buf_ops", "call_usermodehelper_exec_work", "system_unbound_wq",
            "slide_nfulnl_logger", "slide_loggers_0_1", "slide_random_boot_id_data", "slide_init_task",
            "slide_root_task_group", "slide_sysctl_bootid",
        )

        /** Must match CFG_LAYOUT_* indices in target_config.h exactly. */
        val LAYOUT_ORDER = listOf(
            "task_pid", "task_tgid", "task_real_parent", "task_real_cred", "task_cred", "task_comm",
            "task_tasks", "task_thread_info_flags", "task_seccomp", "task_atomic_flags", "cred_uid",
            "cred_securebits", "cred_caps", "cred_security",
        )

        private val WIRE_SIZE = 16 + 6 * 8 + 4 * 4 + SYMBOL_ORDER.size * 8 + LAYOUT_ORDER.size * 4
    }
}
