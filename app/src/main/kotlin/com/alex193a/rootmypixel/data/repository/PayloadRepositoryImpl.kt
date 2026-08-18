package com.alex193a.rootmypixel.data.repository

import android.net.Uri
import android.util.Base64
import com.alex193a.rootmypixel.core.boot.BootImageReader
import com.alex193a.rootmypixel.core.kallsyms.SymbolResolver
import com.alex193a.rootmypixel.core.Result
import com.alex193a.rootmypixel.data.datasource.PayloadLocalDataSource
import com.alex193a.rootmypixel.data.model.toDomain
import com.alex193a.rootmypixel.domain.model.DeviceSnapshot
import com.alex193a.rootmypixel.domain.model.TargetProfile
import com.alex193a.rootmypixel.domain.model.VerifiedPayloads
import com.alex193a.rootmypixel.domain.repository.PayloadError
import com.alex193a.rootmypixel.domain.repository.PayloadRepository
import java.io.File

/**
 * Repository that reads everything from APK assets.
 * Profiles are loaded from assets/profiles.json, exploit .so and ksud
 * binaries are extracted from assets/ on demand.
 */
class PayloadRepositoryImpl(
    private val localDataSource: PayloadLocalDataSource,
    private val filesDir: File,
) : PayloadRepository {

    private var cachedProfiles: List<TargetProfile>? = null
    private val customProfiles = mutableMapOf<String, TargetProfile>()
    private val customConfigs = mutableMapOf<String, File>()

    init {
        loadCustomProfiles()
    }

    override suspend fun resolveTarget(
        snapshot: DeviceSnapshot,
    ): Result<TargetProfile, PayloadError> {
        return when (val result = loadCachedProfiles()) {
            is Result.Error -> result
            is Result.Success -> {
                val profiles = result.data + customProfiles.values

                val targetCodename = snapshot.device.trim()
                val targetKernelRel = snapshot.kernelRelease.trim()
                val targetBuild = snapshot.buildDisplay.trim()

                // /proc/version appends a Git revision to uname -r (for example,
                // "6.6.118-android15-8-g<sha>"). Profiles intentionally keep the
                // stable release prefix. A precise OTA build plus that prefix is the
                // compatibility contract for bundled payloads.
                val exactMatch = profiles.find { profile ->
                    targetCodename.isNotEmpty() &&
                        profile.codename.equals(targetCodename, ignoreCase = true) &&
                        targetBuild.isNotEmpty() &&
                        profile.buildDisplay.equals(targetBuild, ignoreCase = true) &&
                        (targetKernelRel == profile.kernelRelease ||
                            targetKernelRel.startsWith("${profile.kernelRelease}-"))
                }

                if (exactMatch != null) {
                    Result.Success(exactMatch)
                } else {
                    Result.Error(
                        PayloadError.UnsupportedError(
                            "No profile for $targetCodename / $targetKernelRel / ${targetBuild.ifEmpty { "unknown build" }}"
                        )
                    )
                }
            }
        }
    }

    override suspend fun resolveTarget(
        profileId: String,
    ): Result<TargetProfile, PayloadError> {
        customProfiles[profileId]?.let { return Result.Success(it) }
        return when (val result = loadCachedProfiles()) {
            is Result.Error -> result
            is Result.Success -> {
                val profile = result.data.find { it.profileId == profileId }
                if (profile != null) {
                    Result.Success(profile)
                } else {
                    Result.Error(PayloadError.UnsupportedError("Profile $profileId not found"))
                }
            }
        }
    }

    override suspend fun extractPayloads(
        profile: TargetProfile,
        onProgress: (String) -> Unit,
    ): Result<VerifiedPayloads, PayloadError> {
        val payloadDir = File(filesDir, "payloads/${profile.profileId}")
        if (!payloadDir.isDirectory && !payloadDir.mkdirs()) {
            return Result.Error(PayloadError.ExtractionError("Unable to create payload directory"))
        }

        // Extract exploit .so from assets, or use a previously generated generic payload.
        val exploitFile = File(payloadDir, "exploit.so")
        exploitFile.delete()
        val exploitResult = localDataSource.extractAsset(
            assetPath = profile.exploitAsset,
            destination = exploitFile,
            onProgress = onProgress,
        )
        if (exploitResult.isFailure) {
            return Result.Error(
                PayloadError.ExtractionError(
                    "Failed to extract exploit: ${exploitResult.exceptionOrNull()?.message}"
                )
            )
        }
        if (!exploitFile.setExecutable(true, true)) {
            exploitFile.delete()
            return Result.Error(PayloadError.ExtractionError("Unable to make exploit executable"))
        }

        // Extract ksud binary from assets
        val ksudAssetPath = "${PayloadLocalDataSource.KSUD_ASSET_PREFIX}ksud-${profile.kmi}"
        val ksudFile = File(payloadDir, "ksud")
        ksudFile.delete()
        val ksudResult = localDataSource.extractAsset(
            assetPath = ksudAssetPath,
            destination = ksudFile,
            onProgress = onProgress,
        )
        if (ksudResult.isFailure) {
            exploitFile.delete()
            return Result.Error(
                PayloadError.ExtractionError(
                    "Failed to extract ksud: ${ksudResult.exceptionOrNull()?.message}"
                )
            )
        }
        if (!ksudFile.setExecutable(true, true)) {
            exploitFile.delete()
            ksudFile.delete()
            return Result.Error(PayloadError.ExtractionError("Unable to make ksud executable"))
        }

        onProgress("Payloads ready")
        return Result.Success(VerifiedPayloads(exploit = exploitFile, kernelSu = ksudFile, kmi = profile.kmi, targetConfig = customConfigs[profile.profileId]))
    }

    override suspend fun loadTargets(): Result<List<TargetProfile>, PayloadError> {
        return when (val result = loadCachedProfiles()) {
            is Result.Error -> result
            is Result.Success -> Result.Success(result.data + customProfiles.values)
        }
    }

    override suspend fun extractFromBootImage(
        uri: Uri,
        onProgress: (String) -> Unit,
    ): Result<TargetProfile, PayloadError> = try {
        val reader = BootImageReader(localDataSource.contentResolver)
        val kernel = reader.readKernel(uri, onProgress)
        onProgress("Analyzing kallsyms…")
        val release = Regex("Linux version\\s+([^\\s]+)")
            .find(String(kernel, Charsets.ISO_8859_1))
            ?.groupValues?.get(1)
            ?: throw IllegalArgumentException("Kernel release banner not found")
        val started = System.currentTimeMillis()
        val symbols = com.alex193a.rootmypixel.core.kallsyms.KallsymsScanner()
            .resolve(kernel, SymbolResolver.requiredSymbols)
        val elapsed = System.currentTimeMillis() - started
        require(elapsed <= KALLSYMS_BUDGET_MS) {
            "kallsyms analysis exceeded time budget ($elapsed ms)"
        }
        val config = SymbolResolver.toConfig(release, symbols)

        val kmi = when (config.kernelFamily) {
            61 -> "6.1"
            66 -> "6.6"
            else -> throw IllegalArgumentException("Unsupported kernel family ${config.kernelFamily}")
        }
        val id = "custom-${release.replace(Regex("[^A-Za-z0-9._-]"), "_")}"
        val profile = TargetProfile(
            profileId = id,
            codename = "custom",
            kernelRelease = release,
            buildDisplay = id,
            exploitAsset = "exploits/cve-2026-43499-generic-$kmi.so",
            kmi = if (config.kernelFamily == 61) "android14-6.1" else "android15-6.6",
        )
        val customDir = File(filesDir, "custom_profiles").apply { mkdirs() }
        val json = """
            {"profileId":"$id","codename":"custom","kernelRelease":"$release",
             "buildDisplay":"$id","exploitAsset":"${profile.exploitAsset}",
             "kmi":"${profile.kmi}","config":"${Base64.encodeToString(config.toBinary(), Base64.NO_WRAP)}"}
        """.trimIndent()
        File(customDir, "$id.json").writeText(json)
        customProfiles[id] = profile
        customConfigs[id] = File(customDir, "$id.bin").apply { writeBytes(config.toBinary()) }
        cachedProfiles = null // refresh the merged view
        onProgress("Target profile generated")
        Result.Success(profile)
    } catch (error: Throwable) {
        Result.Error(PayloadError.ExtractionError(error.message ?: "Failed to extract target profile"))
    }

    /** Reload user-extracted profiles from internal storage. */
    private fun loadCustomProfiles() {
        val dir = File(filesDir, "custom_profiles")
        if (!dir.isDirectory) return
        dir.listFiles { f -> f.extension == "json" }?.forEach { f ->
            try {
                val raw = f.readText()
                val profileId = Regex("\"profileId\":\"([^\"]+)\"").find(raw)?.groupValues?.get(1) ?: return@forEach
                val codename = Regex("\"codename\":\"([^\"]+)\"").find(raw)?.groupValues?.get(1) ?: "custom"
                val kernelRelease = Regex("\"kernelRelease\":\"([^\"]+)\"").find(raw)?.groupValues?.get(1) ?: return@forEach
                val buildDisplay = Regex("\"buildDisplay\":\"([^\"]+)\"").find(raw)?.groupValues?.get(1) ?: profileId
                val exploitAsset = Regex("\"exploitAsset\":\"([^\"]+)\"").find(raw)?.groupValues?.get(1)
                    ?: "exploits/cve-2026-43499-generic-6.1.so"
                val kmi = Regex("\"kmi\":\"([^\"]+)\"").find(raw)?.groupValues?.get(1) ?: "android14-6.1"
                val b64 = Regex("\"config\":\"([^\"]+)\"").find(raw)?.groupValues?.get(1)
                customProfiles[profileId] = TargetProfile(profileId, codename, kernelRelease, buildDisplay, exploitAsset, kmi)
                if (b64 != null) {
                    val bin = File(dir, "$profileId.bin")
                    if (!bin.exists()) bin.writeBytes(Base64.decode(b64, Base64.NO_WRAP))
                    customConfigs[profileId] = bin
                }
            } catch (_: Throwable) {
                // ignore malformed custom profile
            }
        }
    }

    companion object {
        private const val KALLSYMS_BUDGET_MS = 30_000L
    }

    private fun loadCachedProfiles(): Result<List<TargetProfile>, PayloadError> {
        cachedProfiles?.let { return Result.Success(it) }

        return localDataSource.loadProfiles().fold(
            onSuccess = { dtos ->
                val profiles = dtos.map { it.toDomain() }
                cachedProfiles = profiles
                Result.Success(profiles)
            },
            onFailure = { throwable ->
                Result.Error(
                    PayloadError.ExtractionError(
                        throwable.message ?: "Failed to load profiles.json"
                    )
                )
            }
        )
    }
}
