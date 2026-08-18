package com.alex193a.rootmypixel.core.kallsyms

import com.alex193a.rootmypixel.domain.model.TargetConfig

object SymbolResolver {
    val requiredSymbols = setOf(
        "init_task", "root_task_group", "selinux_enforcing", "selinux_blob_sizes",
        "security_hook_heads", "kmalloc_caches", "anon_pipe_buf_ops",
        "call_usermodehelper_exec_work", "system_unbound_wq", "ashmem_ioctl",
        "ashmem_mmap", "ashmem_open", "ashmem_release", "ashmem_show_fdinfo",
        "configfs_read_iter", "configfs_bin_write_iter", "copy_splice_read", "noop_llseek",
    )

    fun toConfig(kernelRelease: String, symbols: Map<String, Long>, pageSize: Int = 4096): TargetConfig {
        val family = when {
            kernelRelease.contains("6.1") -> 61
            kernelRelease.contains("6.6") -> 66
            else -> error("Unsupported kernel family: $kernelRelease")
        }
        val base = if (family == 61) 0xffffffc008000000UL.toLong() else 0xffffffc080000000UL.toLong()
        val offsets = symbols.mapValues { (_, address) -> if (address >= base) address - base else address }
        val config = TargetConfig(
            kernelFamily = family,
            pageSize = pageSize,
            kimageTextBase = base,
            p0PageOffset = 0xffffff8000000000UL.toLong(),
            p0PhysOffset = 0x80000000L,
            directMapBase = 0xffffff8000000000UL.toLong(),
            directMapEnd = 0xffffff9000000000UL.toLong(),
            vmemmapStart = 0xfffffffe00000000UL.toLong(),
            mmStructSize = if (family == 61) 0x400 else 0x500,
            kmallocCgroupType = if (family == 61) 1 else 2,
            kmallocCacheTypes = if (family == 61) 3 else 4,
            kmallocPipeIndex = 11,
            symbols = offsets,
            layouts = defaultLayouts(family),
        )
        config.validate()
        return config
    }

    private fun defaultLayouts(family: Int): Map<String, Int> = if (family == 61) mapOf(
        "task_pid" to 0x630, "task_tgid" to 0x634, "task_real_parent" to 0x640,
        "task_real_cred" to 0x830, "task_cred" to 0x838, "task_comm" to 0x848,
        "task_tasks" to 0x550, "task_thread_info_flags" to 0, "task_seccomp" to 0x900,
        "task_atomic_flags" to 0x5f0, "cred_uid" to 4, "cred_securebits" to 36,
        "cred_caps" to 40, "cred_security" to 120, "selinux_cred_blob" to 0,
        "selinux_cred_osid" to 0, "selinux_cred_sid" to 4,
    ) else mapOf(
        "task_pid" to 0x618, "task_tgid" to 0x61c, "task_real_parent" to 0x628,
        "task_real_cred" to 0x818, "task_cred" to 0x820, "task_comm" to 0x830,
        "task_tasks" to 0x550, "task_thread_info_flags" to 0, "task_seccomp" to 0x8e8,
        "task_atomic_flags" to 0x5d8, "cred_uid" to 8, "cred_securebits" to 40,
        "cred_caps" to 48, "cred_security" to 128, "selinux_cred_blob" to 0,
        "selinux_cred_osid" to 0, "selinux_cred_sid" to 4,
    )
}
