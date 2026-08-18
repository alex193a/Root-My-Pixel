package com.alex193a.rootmypixel.data.repository

import android.net.Uri
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
        return loadCachedProfiles()
    }

    override suspend fun extractFromBootImage(
        uri: Uri,
        onProgress: (String) -> Unit,
    ): Result<TargetProfile, PayloadError> = try {
        val reader = BootImageReader(localDataSource.contentResolver)
        val kernel = reader.readKernel(uri, onProgress)
        onProgress("Analyzing kallsyms…")
        val release = Regex("Linux version\\s+([^\\s]+)").find(String(kernel, Charsets.ISO_8859_1))?.groupValues?.get(1)
            ?: throw IllegalArgumentException("Kernel release banner not found")
        val symbols = com.alex193a.rootmypixel.core.kallsyms.KallsymsScanner().resolve(kernel, SymbolResolver.requiredSymbols)
        val config = SymbolResolver.toConfig(release, symbols)
        val id = "custom-${release.replace(Regex("[^A-Za-z0-9._-]"), "_") }"
        val profile = TargetProfile(id, "custom", release, id, "exploits/cve-2026-43499-generic-${config.kernelFamily / 10}.${config.kernelFamily % 10}.so", "android${if (config.kernelFamily == 61) 14 else 15}-${config.kernelFamily / 10}.${config.kernelFamily % 10}")
        val customDir = File(filesDir, "custom_profiles").apply { mkdirs() }
        val configFile = File(customDir, "$id.bin").apply { writeBytes(config.toBinary()) }
        File(customDir, "$id.json").writeText("{\"profileId\":\"$id\",\"kernelRelease\":\"$release\",\"config\":\"${android.util.Base64.encodeToString(config.toBinary(), android.util.Base64.NO_WRAP)}\"}")
        customProfiles[id] = profile
        customConfigs[id] = configFile
        onProgress("Target profile generated")
        Result.Success(profile)
    } catch (error: Throwable) {
        Result.Error(PayloadError.ExtractionError(error.message ?: "Failed to extract target profile"))
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
