package com.alex193a.rootmypixel.domain.model

data class InstallUiState(
    val phase: InstallPhase = InstallPhase.Checking,
    val message: String = "",
    val probeOutput: String = "",
    val log: String = "",
    /** True only for the successful install run that still has a usable CVE root transport. */
    val canUnrootCurrentSession: Boolean = false,
    /** Non-null while unroot is paused waiting for an explicit reboot decision. */
    val unrootWarning: UnrootWarningUi? = null,
    /** False for deterministic/terminal failures such as ROUTE_DISABLED. */
    val retryAllowed: Boolean = true,
) {
    val busy: Boolean
        get() = phase in setOf(
            InstallPhase.Checking,
            InstallPhase.Downloading,
            InstallPhase.Exploiting,
            InstallPhase.LoadingKernelSu,
        )
}

data class UnrootWarningUi(
    val failedItemsText: String,
)
