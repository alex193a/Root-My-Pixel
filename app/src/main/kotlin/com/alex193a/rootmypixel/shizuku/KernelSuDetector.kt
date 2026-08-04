package com.alex193a.rootmypixel.shizuku

import android.content.ComponentName
import android.content.Context
import android.content.ServiceConnection
import android.content.pm.PackageManager
import android.os.IBinder
import rikka.shizuku.Shizuku
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

object KernelSuDetector {
    fun isActive(context: Context): Boolean {
        val available = runCatching {
            Shizuku.pingBinder() &&
                Shizuku.isPreV11().not() &&
                Shizuku.getUid() == 2000 &&
                Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        }.getOrDefault(false)
        if (!available) return false

        val args = Shizuku.UserServiceArgs(
            ComponentName(context.packageName, ExploitService::class.java.name)
        )
            .daemon(false)
            .processNameSuffix("exploit_service")
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
            connected.await(SERVICE_TIMEOUT_SECONDS, TimeUnit.SECONDS)
            val output = service?.exec(
                "/data/local/tmp/ksud-pixel debug version 2>/dev/null || true"
            ).orEmpty()
            ROOT_VERSION.find(output)?.groupValues?.get(1)?.toIntOrNull()?.let { it > 0 } == true
        } catch (_: Exception) {
            false
        } finally {
            runCatching { Shizuku.unbindUserService(args, connection, true) }
        }
    }

    private const val SERVICE_TIMEOUT_SECONDS = 5L
    private val ROOT_VERSION = Regex("Kernel Version: ([0-9]+)")
}
