package com.alex193a.rootmypixel.domain.model

import java.io.File

/**
 * Verified payload artifacts extracted from APK assets for a target profile.
 */
data class VerifiedPayloads(
    val exploit: File,
    val kernelSu: File,
    val kmi: String,
    val targetConfig: File? = null,
)
