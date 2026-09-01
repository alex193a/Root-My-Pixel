package com.alex193a.rootmypixel.utils

internal object KernelSuInstallChecks {
    private val versionLine = Regex("(?m)^version:\\s*([1-9][0-9]*)\\s*$")
    private val kernelModuleLine = Regex("(?m)^kernelsu\\s+.+$")
    private val signatureLine = Regex(
        """^size:\s*(0[xX][0-9a-fA-F]+|[0-9]+),\s*hash:\s*([0-9a-fA-F]{64})$""",
    )

    data class ManagerSignature(
        val size: Int,
        val hash: String,
    )

    fun debugInfoShowsActiveKernelSu(output: String): Boolean =
        versionLine.containsMatchIn(output)

    fun procModulesShowsActiveKernelSu(output: String): Boolean =
        kernelModuleLine.containsMatchIn(output)

    fun parseManagerSignature(output: String): ManagerSignature? {
        val match = signatureLine.matchEntire(output.trim()) ?: return null
        val rawSize = match.groupValues[1]
        val size = if (rawSize.startsWith("0x", ignoreCase = true)) {
            rawSize.drop(2).toIntOrNull(16)
        } else {
            rawSize.toIntOrNull()
        } ?: return null

        return ManagerSignature(
            size = size,
            hash = match.groupValues[2].lowercase(),
        )
    }

    fun isTrustedManagerSignature(signature: ManagerSignature): Boolean =
        signature in TRUSTED_MANAGER_SIGNATURES

    private val TRUSTED_MANAGER_SIGNATURES = setOf(
        ManagerSignature(
            size = 0x377,
            hash = "d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64",
        ),
    )
}
