package com.alex193a.rootmypixel.shizuku

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import rikka.shizuku.Shizuku
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

object KernelSuDetector {

    /** Installs in flight app-wide; probing is suppressed while any is running. */
    private val installsInFlight = AtomicInteger(0)

    fun beginInstall() {
        installsInFlight.incrementAndGet()
    }

    fun endInstall() {
        installsInFlight.updateAndGet { if (it > 0) it - 1 else 0 }
    }

    fun isInstallInFlight(): Boolean = installsInFlight.get() > 0

    /**
     * Whether KernelSU is live *right now*, per ksud's kernel-side version.
     * Deliberately ignores on-disk paths: `/data/adb/ksu` survives reboots.
     */
    fun isActive(context: Context): Boolean {
        if (isInstallInFlight()) return false

        val available = runCatching {
            Shizuku.pingBinder() &&
                Shizuku.isPreV11().not() &&
                Shizuku.getUid() == 2000 &&
                Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        }.getOrDefault(false)
        if (!available) return false

        val args = Shizuku.UserServiceArgs(
            ComponentName(context.packageName, ProbeService::class.java.name)
        )
            .daemon(false)
            .processNameSuffix("probe_service")
            .version(1)
        val connected = CountDownLatch(1)
        // Read only after await() succeeds — that is the happens-before edge.
        var service: IExploitService? = null
        val connection = object : ServiceConnection {
            override fun onServiceConnected(name: ComponentName?, binder: IBinder?) {
                service = IExploitService.Stub.asInterface(binder)
                connected.countDown()
            }

            override fun onServiceDisconnected(name: ComponentName?) {
                service = null
            }
        }

        var bound = false
        return try {
            Shizuku.bindUserService(args, connection)
            bound = true
            if (!connected.await(SERVICE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) return false
            val output = service?.exec(
                "$KSUD_PATH debug version 2>/dev/null || true"
            ).orEmpty()
            val version = parseKernelVersion(output)
            version != null && version > 0
        } catch (_: Exception) {
            false
        } finally {
            if (bound) {
                runCatching { Shizuku.unbindUserService(args, connection, true) }
            }
        }
    }

    /**
     * Kernel-side version from `ksud debug version`, or null if ksud did not
     * answer. Callers rely on null ("no answer") differing from 0 ("not live").
     */
    fun parseKernelVersion(output: String): Int? =
        KERNEL_VERSION.find(output)?.groupValues?.get(1)?.toIntOrNull()

    const val KSUD_PATH = "/data/local/tmp/ksud-pixel"

    private const val SERVICE_TIMEOUT_SECONDS = 5L
    private val KERNEL_VERSION = Regex("Kernel Version:\\s*(-?[0-9]+)")
}
