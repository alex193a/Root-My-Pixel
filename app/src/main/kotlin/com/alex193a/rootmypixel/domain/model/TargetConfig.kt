package com.alex193a.rootmypixel.domain.model

import java.nio.ByteBuffer
import java.nio.ByteOrder

/** Runtime configuration shared with the generic native payload. */
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
        require(pageSize == 4096 || pageSize == 16384) { "Unsupported page size" }
        require(mmStructSize > 0 && mmStructSize <= 0x2000) { "Invalid mm_struct size" }
        require(directMapEnd > directMapBase) { "Invalid direct map" }
        listOf("init_task", "selinux_enforcing", "kmalloc_caches").forEach {
            require((symbols[it] ?: 0L) != 0L) { "Required symbol not resolved: $it" }
        }
        return kotlin.Result.success(Unit)
    }

    /** Packed wire format consumed by target_config.c. */
    fun toBinary(): ByteArray {
        val out = ByteBuffer.allocate(WIRE_SIZE).order(ByteOrder.LITTLE_ENDIAN)
        out.putInt(MAGIC).putInt(VERSION).putInt(kernelFamily).putInt(pageSize)
        out.putLong(kimageTextBase).putLong(p0PageOffset).putLong(p0PhysOffset)
            .putLong(directMapBase).putLong(directMapEnd).putLong(vmemmapStart)
        out.putInt(mmStructSize).putInt(kmallocCgroupType).putInt(kmallocCacheTypes).putInt(kmallocPipeIndex)
        SYMBOL_ORDER.forEach { out.putLong(symbols[it] ?: 0L) }
        LAYOUT_ORDER.forEach { out.putInt(layouts[it] ?: 0) }
        return out.array()
    }

    companion object {
        const val MAGIC = 0x50584c43
        const val VERSION = 1
        private val SYMBOL_ORDER = listOf(
            "ashmem_ioctl", "ashmem_mmap", "ashmem_open", "ashmem_release", "ashmem_show_fdinfo",
            "ashmem_misc_fops", "ashmem_fops", "ashmem_compat_ioctl", "configfs_read_iter",
            "configfs_bin_write_iter", "copy_splice_read", "noop_llseek", "init_task", "root_task_group",
            "selinux_enforcing", "selinux_blob_sizes", "security_hook_heads", "kmalloc_caches",
            "anon_pipe_buf_ops", "call_usermodehelper_exec_work", "system_unbound_wq",
            "slide_nfulnl_logger", "slide_loggers_0_1", "slide_random_boot_id_data", "slide_init_task",
            "slide_root_task_group", "slide_sysctl_bootid",
        )
        private val LAYOUT_ORDER = listOf(
            "task_pid", "task_tgid", "task_real_parent", "task_real_cred", "task_cred", "task_comm",
            "task_tasks", "task_thread_info_flags", "task_seccomp", "task_atomic_flags", "cred_uid",
            "cred_securebits", "cred_caps", "cred_security", "selinux_cred_blob", "selinux_cred_osid", "selinux_cred_sid",
        )
        private val WIRE_SIZE = 16 + 6 * 8 + 16 + SYMBOL_ORDER.size * 8 + LAYOUT_ORDER.size * 4
    }
}
