package com.alex193a.rootmypixel.feature.main

import android.app.Application
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Handler
import android.os.Looper
import android.os.Process
import androidx.core.content.FileProvider
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.alex193a.rootmypixel.R
import com.alex193a.rootmypixel.core.Result
import com.alex193a.rootmypixel.domain.model.DeviceSnapshot
import com.alex193a.rootmypixel.domain.model.InstallPhase
import com.alex193a.rootmypixel.domain.model.InstallUiState
import com.alex193a.rootmypixel.domain.usecase.ResolveTargetUseCase
import com.alex193a.rootmypixel.feature.install.InstallActivity
import com.alex193a.rootmypixel.shizuku.KernelSuDetector
import com.alex193a.rootmypixel.utils.NativeProbe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.koin.java.KoinJavaComponent.get
import rikka.shizuku.Shizuku
import java.io.File

class MainViewModel(application: Application) : AndroidViewModel(application) {
    private val app = application
    private val resolveTargetUseCase: ResolveTargetUseCase by lazy {
        get(ResolveTargetUseCase::class.java)
    }

    private val mutableState = MutableStateFlow(InstallUiState())
    private val mutableShizukuAvailable = MutableStateFlow(false)
    private val mutableReSukiSuInstalled = MutableStateFlow(false)
    private var refreshJob: Job? = null

    val state: StateFlow<InstallUiState> = mutableState.asStateFlow()
    val shizukuAvailable: StateFlow<Boolean> = mutableShizukuAvailable.asStateFlow()
    val reSukiSuInstalled: StateFlow<Boolean> = mutableReSukiSuInstalled.asStateFlow()

    private val shizukuPermissionHandler = Handler(Looper.getMainLooper())
    private val shizukuListener = Shizuku.OnBinderReceivedListener {
        shizukuPermissionHandler.post { checkShizuku() }
    }
    private val shizukuDeadListener = Shizuku.OnBinderDeadListener {
        shizukuPermissionHandler.post { mutableShizukuAvailable.value = false }
    }
    private val shizukuPermissionListener = Shizuku.OnRequestPermissionResultListener { code, result ->
        if (code == SHIZUKU_PERMISSION_CODE) {
            shizukuPermissionHandler.post { checkShizuku() }
        }
    }

    init {
        refresh()
    }

    fun initShizuku() {
        Shizuku.addBinderReceivedListener(shizukuListener)
        Shizuku.addBinderDeadListener(shizukuDeadListener)
        Shizuku.addRequestPermissionResultListener(shizukuPermissionListener)

        if (Shizuku.pingBinder()) {
            checkShizuku()
        }
    }

    private fun checkShizuku() {
        val available = try {
            Shizuku.pingBinder() &&
            Shizuku.isPreV11().not() &&
            Shizuku.getUid() == 2000 &&
            Shizuku.checkSelfPermission() == PackageManager.PERMISSION_GRANTED
        } catch (_: Exception) {
            false
        }

        if (!available && Shizuku.pingBinder() && Shizuku.isPreV11().not()) {
            if (Shizuku.checkSelfPermission() != PackageManager.PERMISSION_GRANTED) {
                Shizuku.requestPermission(SHIZUKU_PERMISSION_CODE)
            }
        }

        mutableShizukuAvailable.value = available
    }

    override fun onCleared() {
        super.onCleared()
        Shizuku.removeBinderReceivedListener(shizukuListener)
        Shizuku.removeBinderDeadListener(shizukuDeadListener)
        Shizuku.removeRequestPermissionResultListener(shizukuPermissionListener)
    }

    fun refresh() {
        if (refreshJob?.isActive == true) return
        refreshJob?.cancel()
        refreshJob = viewModelScope.launch(Dispatchers.IO) {
            mutableState.value = InstallUiState(phase = InstallPhase.Checking)

            try {
                mutableReSukiSuInstalled.value = app.packageManager
                    .getLaunchIntentForPackage("com.resukisu.resukisu") != null
                val probe = NativeProbe.run()
                if (NativeProbe.isKernelSuActive() || KernelSuDetector.isActive(app)) {
                    mutableState.value = InstallUiState(
                        phase = InstallPhase.Installed,
                        message = app.getString(R.string.status_ksu_active),
                        probeOutput = probe,
                        log = probe,
                    )
                    return@launch
                }
                val deviceInfo = NativeProbe.readDeviceSnapshot()
                val snapshot = DeviceSnapshot(
                    kernelRelease = deviceInfo.kernelRelease,
                    kernelVersion = deviceInfo.kernelVersion,
                    buildDisplay = deviceInfo.buildDisplay,
                    sdkVersion = deviceInfo.sdkVersion,
                    abi = deviceInfo.abi,
                    pageSize = deviceInfo.pageSize,
                    model = deviceInfo.model,
                    device = deviceInfo.device,
                )

                when (val result = resolveTargetUseCase(snapshot)) {
                    is Result.Success -> {
                        val profile = result.data
                        mutableState.value = InstallUiState(
                            phase = InstallPhase.Ready,
                            message = app.getString(R.string.status_not_installed),
                            probeOutput = probe,
                            log = buildString {
                                appendLine(probe)
                                appendLine("Matched profile: ${profile.profileId}")
                                appendLine("Device: ${deviceInfo.model} (${deviceInfo.device})")
                                appendLine("Kernel: ${deviceInfo.kernelRelease}")
                                appendLine("Build: ${deviceInfo.buildDisplay}")
                                appendLine("SDK: ${deviceInfo.sdkVersion}  ABI: ${deviceInfo.abi}")
                            },
                        )
                    }
                    is Result.Error -> {
                        mutableState.value = InstallUiState(
                            phase = InstallPhase.Failed,
                            message = app.getString(R.string.status_support_failed),
                            probeOutput = probe,
                            log = "$probe\n[-] ${result.error.message}",
                        )
                    }
                }
            } catch (error: Throwable) {
                if (error is CancellationException) throw error
                mutableState.value = InstallUiState(
                    phase = InstallPhase.Failed,
                    message = app.getString(R.string.status_support_failed),
                    log = "[-] ${error.message ?: error.javaClass.simpleName}",
                )
            }
        }
    }

    fun install() {
        val intent = Intent(app, InstallActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        app.startActivity(intent)
    }

    fun softReboot() {
        viewModelScope.launch(Dispatchers.IO) {
            val helper = File(app.applicationInfo.nativeLibraryDir, "libcve43499root.so")
            if (!helper.exists()) return@launch

            try {
                val result = runCatching {
                    val process = ProcessBuilder(
                        helper.absolutePath, "-c",
                        "killall -9 system_server 2>/dev/null; true"
                    ).redirectErrorStream(true).start()
                    process.inputStream.bufferedReader().use { it.readText() }
                    process.waitFor()
                }
                val output = result.getOrDefault("daemon unreachable")
                android.util.Log.i("RootMyPixel", "[softReboot] $output")
            } catch (_: Exception) { }
        }
    }

    fun exportLog() {
        val logFile = File(app.filesDir, "exploit.log")
        if (!logFile.exists()) return

        val uri = FileProvider.getUriForFile(app, "${app.packageName}.provider", logFile)
        val shareIntent = Intent(Intent.ACTION_SEND).apply {
            type = "text/plain"
            putExtra(Intent.EXTRA_STREAM, uri)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        val chooserIntent = Intent.createChooser(shareIntent, "Export exploit.log").apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }
        app.startActivity(chooserIntent)
    }

    companion object {
        private const val SHIZUKU_PERMISSION_CODE = 101
    }
}
