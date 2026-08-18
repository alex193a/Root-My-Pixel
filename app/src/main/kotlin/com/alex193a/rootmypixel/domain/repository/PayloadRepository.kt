package com.alex193a.rootmypixel.domain.repository

import com.alex193a.rootmypixel.core.Error
import com.alex193a.rootmypixel.core.Result
import com.alex193a.rootmypixel.domain.model.DeviceSnapshot
import com.alex193a.rootmypixel.domain.model.TargetProfile
import android.net.Uri
import com.alex193a.rootmypixel.domain.model.VerifiedPayloads

/**
 * Repository for resolving target profiles and extracting bundled payloads.
 * Everything ships inside the APK.
 */
interface PayloadRepository {
    /**
     * Resolve the best-matching target profile for the given device snapshot.
     */
    suspend fun resolveTarget(snapshot: DeviceSnapshot): Result<TargetProfile, PayloadError>

    /**
     * Resolve a specific profile by ID (manual selection).
     */
    suspend fun resolveTarget(profileId: String): Result<TargetProfile, PayloadError>

    /**
     * Extract bundled payload artifacts for a resolved profile from APK assets.
     * [onProgress] is called with description strings during extraction.
     */
    suspend fun extractPayloads(
        profile: TargetProfile,
        onProgress: (String) -> Unit,
    ): Result<VerifiedPayloads, PayloadError>

    /**
     * Load all available target profiles bundled in the app.
     */
    suspend fun loadTargets(): Result<List<TargetProfile>, PayloadError>

    /** Extracts a kernel from boot.img/factory ZIP and creates a cached custom profile. */
    suspend fun extractFromBootImage(
        uri: Uri,
        onProgress: (String) -> Unit = {},
    ): Result<TargetProfile, PayloadError>
}

sealed interface PayloadError : Error {
    data class UnsupportedError(override val message: String) : PayloadError
    data class ExtractionError(override val message: String) : PayloadError
    data class UnknownError(override val message: String) : PayloadError
}
