package com.alex193a.rootmypixel.feature.main

import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.content.pm.PackageManager
import android.os.Handler
import android.os.Looper
import android.os.Process
import android.os.SystemClock
import androidx.core.content.FileProvider
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.alex193a.rootmypixel.R
import com.alex193a.rootmypixel.core.Result
import com.alex193a.rootmypixel.domain.model.DeviceSnapshot
import com.alex193a.rootmypixel.domain.model.InstallPhase
import com.alex193a.rootmypixel.domain.model.InstallUiState
import com.alex193a.rootmypixel.domain.repository.PayloadRepository
import com.alex193a.rootmypixel.domain.usecase.ResolveTargetUseCase
import com.alex193a.rootmypixel.feature.install.InstallActivity
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
    private val payloadRepository: PayloadRepository by lazy {
        get(PayloadRepository::class.java)
    }

    private val mutableState = MutableStateFlow(InstallUiState())
    private val mutableShizukuAvailable = MutableStateFlow(false)
    private val mutableReSukiSuInstalled = MutableStateFlow(false)
    private val mutableUptimeExceeded = MutableStateFlow(false)
    private val prefs = app.getSharedPreferences("custom_profile", Context.MODE_PRIVATE)
    private var refreshJob: Job? = null
    private var customProfileId: String? = prefs.getString(KEY_CUSTOM_PROFILE_ID, null)

    val state: StateFlow<InstallUiState> = mutableState.asStateFlow()
    val shizukuAvailable: StateFlow<Boolean> = mutableShizukuAvailable.asStateFlow()
    val reSukiSuInstalled: StateFlow<Boolean> = mutableReSukiSuInstalled.asStateFlow()
    val uptimeExceeded: StateFlow<Boolean> = mutableUptimeExceeded.asStateFlow()


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
            mutableUptimeExceeded.value = SystemClock.elapsedRealtime() > UPTIME_THRESHOLD_MS

            try {
                mutableReSukiSuInstalled.value = app.packageManager
                    .getLaunchIntentForPackage("com.resukisu.resukisu") != null
                val probe = NativeProbe.run()
                if (NativeProbe.isKernelSuActive()) {
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
                        val customId = customProfileId
                        if (customId != null) {
                            // A user-extracted profile is already available for
                            // this device; keep it installable across recreations.
                            mutableState.value = InstallUiState(
                                phase = InstallPhase.Ready,
                                message = app.getString(R.string.status_custom_profile_ready),
                                probeOutput = probe,
                                log = "$probe\n[+] Custom profile ready: $customId",
                            )
                        } else {
                            mutableState.value = InstallUiState(
                                phase = InstallPhase.Failed,
                                message = app.getString(R.string.status_support_failed),
                                probeOutput = probe,
                                log = "$probe\n[-] ${result.error.message}",
                            )
                        }
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

    /**
     * Extracts a custom target profile from a user-provided boot.img or factory
     * image. Runs on the main screen for unsupported devices (where the Install
     * button is disabled), then hands the generated profile to InstallActivity.
     */
    fun extractCustomProfile(uri: Uri) {
        if (refreshJob?.isActive == true) return
        refreshJob?.cancel()
        refreshJob = viewModelScope.launch(Dispatchers.IO) {
            mutableState.value = mutableState.value.copy(
                phase = InstallPhase.Downloading,
                message = app.getString(R.string.status_extracting_boot_image),
            )
            appendLog("[*] Reading selected boot image…")
            when (val result = payloadRepository.extractFromBootImage(uri) { step ->
                appendLog("[*] $step")
            }) {
                is Result.Success -> {
                    customProfileId = result.data.profileId
                    prefs.edit().putString(KEY_CUSTOM_PROFILE_ID, result.data.profileId).apply()
                    mutableState.value = mutableState.value.copy(
                        phase = InstallPhase.Ready,
                        message = app.getString(R.string.status_custom_profile_ready),
                    )
                    appendLog("[+] Custom profile generated: ${result.data.profileId}")
                    appendLog("[+] Tap Install to continue with this profile")
                }
                is Result.Error -> {
                    appendLog("[-] ${result.error.message}")
                    mutableState.value = mutableState.value.copy(
                        phase = InstallPhase.Failed,
                        message = app.getString(R.string.status_support_failed),
                    )
                }
            }
        }
    }

    fun install() {
        val intent = Intent(app, InstallActivity::class.java).apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            customProfileId?.let { putExtra(InstallActivity.EXTRA_PROFILE_ID, it) }
        }
        app.startActivity(intent)
    }

    private fun appendLog(line: String) {
        val clean = line.trim()
        if (clean.isBlank()) return
        mutableState.value = mutableState.value.copy(
            log = (mutableState.value.log + "\n" + clean).trim().takeLast(MAX_LOG_CHARS),
        )
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
        private const val UPTIME_THRESHOLD_MS = 5 * 60 * 1000L // 5 minutes
        private const val MAX_LOG_CHARS = 5 * 1024 * 1024
        private const val KEY_CUSTOM_PROFILE_ID = "custom_profile_id"
    }
}
