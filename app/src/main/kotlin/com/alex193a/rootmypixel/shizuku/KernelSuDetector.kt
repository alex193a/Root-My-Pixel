package com.alex193a.rootmypixel.shizuku

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import rikka.shizuku.Shizuku
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** Detects modern ReSukiSU through its su interface instead of legacy nodes. */
object KernelSuDetector {
    fun isActive(context: Context): Boolean {
        if (isDirectAppSuActive()) return true
        return isShizukuShellSuActive(context)
    }

    private fun isDirectAppSuActive(): Boolean = runCatching {
        val process = ProcessBuilder(
            "/system/bin/su",
            "-c",
            "echo $PROBE_MARKER; id -u",
        ).redirectErrorStream(true).start()
        if (!process.waitFor(PROBE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            process.waitFor(1, TimeUnit.SECONDS)
            return@runCatching false
        }
        isRootShellProbeOutput(process.inputStream.bufferedReader().use { it.readText() })
    }.getOrDefault(false)

    private fun isShizukuShellSuActive(context: Context): Boolean {
        val shizukuReady = runCatching {
            Shizuku.pingBinder() &&
                !Shizuku.isPreV11() &&
                Shizuku.getUid() == 2000 &&
                Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        }.getOrDefault(false)
        if (!shizukuReady) return false

        val args = Shizuku.UserServiceArgs(
            ComponentName(context.packageName, ExploitService::class.java.name),
        )
            .daemon(false)
            .processNameSuffix("ksu_detector")
            .version(1)
        val connected = CountDownLatch(1)
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

        return try {
            Shizuku.bindUserService(args, connection)
            if (!connected.await(SERVICE_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                false
            } else {
                isRootShellProbeOutput(service?.exec(ROOT_PROBE_COMMAND).orEmpty())
            }
        } catch (_: Exception) {
            false
        } finally {
            runCatching { Shizuku.unbindUserService(args, connection, true) }
        }
    }

    internal fun isRootShellProbeOutput(output: String): Boolean {
        val lines = output.lineSequence().map(String::trim).filter(String::isNotEmpty).toSet()
        return PROBE_MARKER in lines && "0" in lines
    }

    private const val SERVICE_TIMEOUT_SECONDS = 5L
    private const val PROBE_TIMEOUT_SECONDS = 5L
    private const val PROBE_MARKER = "ROOT_MY_PIXEL_KSU_ACTIVE"
    private const val ROOT_PROBE_COMMAND =
        "/system/bin/su -c 'echo $PROBE_MARKER; id -u' </dev/null 2>/dev/null"
}
