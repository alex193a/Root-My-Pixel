package com.alex193a.rootmypixel.feature.install

import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.activity.viewModels
import androidx.annotation.StringRes
import androidx.compose.animation.AnimatedContent
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.CloudDownload
import androidx.compose.material.icons.rounded.ContentCopy
import androidx.compose.material.icons.rounded.DeleteForever
import androidx.compose.material.icons.rounded.Error
import androidx.compose.material.icons.rounded.Memory
import androidx.compose.material.icons.rounded.Security
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.alex193a.rootmypixel.R
import com.alex193a.rootmypixel.domain.model.InstallPhase
import com.alex193a.rootmypixel.ui.components.UnrootIncompleteSheet
import com.alex193a.rootmypixel.ui.theme.RootMyPixelTheme
import kotlinx.coroutines.delay
import kotlin.time.Duration.Companion.milliseconds

class InstallActivity : ComponentActivity() {
    private val installViewModel by viewModels<InstallViewModel>()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        window.addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON)

        val profileId = intent.getStringExtra(EXTRA_PROFILE_ID)
        val permissiveOnly = intent.getBooleanExtra(EXTRA_PERMISSIVE_ONLY, false)
        if (savedInstanceState == null) {
            installViewModel.install(profileId, permissiveOnly)
        }

        setContent {
            val installState by installViewModel.state.collectAsStateWithLifecycle()
            BackHandler(enabled = installState.busy) {}

            RootMyPixelTheme {
                Scaffold { padding ->
                    InstallScreen(
                        installState = installState,
                        permissiveOnly = permissiveOnly,
                        onRetry = { installViewModel.install(profileId, permissiveOnly) },
                        onSoftReboot = { installViewModel.softReboot() },
                        onUnroot = installViewModel::unrootCurrentSession,
                        onCancelUnrootReboot = installViewModel::cancelUnrootReboot,
                        onRebootAnyway = installViewModel::continueUnrootReboot,
                        onClose = { finish() },
                        modifier = Modifier.padding(padding),
                    )
                }
            }
        }
    }

    companion object {
        const val EXTRA_PROFILE_ID = "profile_id"
        const val EXTRA_PERMISSIVE_ONLY = "permissive_only"
    }
}

// ── Step definitions ──────────────────────────────────────────────

private data class InstallerStep(
    @StringRes val title: Int,
    @StringRes val detail: Int,
    val icon: ImageVector,
)

private val installerStepsFull = listOf(
    InstallerStep(R.string.step_support_title, R.string.step_support_detail, Icons.Rounded.Security),
    InstallerStep(R.string.step_download_title, R.string.step_download_detail, Icons.Rounded.CloudDownload),
    InstallerStep(R.string.step_exploit_title, R.string.step_exploit_detail, Icons.Rounded.Memory),
    InstallerStep(R.string.step_ksu_title, R.string.step_ksu_detail, Icons.Rounded.Check),
)

private val installerStepsPermissive = listOf(
    InstallerStep(R.string.step_support_title, R.string.step_support_detail, Icons.Rounded.Security),
    InstallerStep(R.string.step_download_title, R.string.step_download_detail, Icons.Rounded.CloudDownload),
    InstallerStep(R.string.step_exploit_title, R.string.step_exploit_detail, Icons.Rounded.Memory),
)

// ── Screen ────────────────────────────────────────────────────────

@Composable
private fun InstallScreen(
    installState: com.alex193a.rootmypixel.domain.model.InstallUiState,
    permissiveOnly: Boolean,
    onRetry: () -> Unit,
    onSoftReboot: () -> Unit,
    onUnroot: () -> Unit,
    onCancelUnrootReboot: () -> Unit,
    onRebootAnyway: () -> Unit,
    onClose: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val logScrollState = rememberScrollState()
    val steps = if (permissiveOnly) installerStepsPermissive else installerStepsFull
    var showUnrootDialog by remember { mutableStateOf(false) }

    if (showUnrootDialog) {
        AlertDialog(
            onDismissRequest = { showUnrootDialog = false },
            icon = {
                Icon(
                    imageVector = Icons.Rounded.DeleteForever,
                    contentDescription = null,
                    tint = MaterialTheme.colorScheme.error,
                )
            },
            title = { Text(stringResource(R.string.unroot_dialog_title)) },
            text = { Text(stringResource(R.string.unroot_dialog_message)) },
            confirmButton = {
                Button(
                    onClick = {
                        showUnrootDialog = false
                        onUnroot()
                    },
                    colors = ButtonDefaults.buttonColors(
                        containerColor = MaterialTheme.colorScheme.error,
                        contentColor = MaterialTheme.colorScheme.onError,
                    ),
                ) {
                    Text(stringResource(R.string.action_confirm_unroot))
                }
            },
            dismissButton = {
                OutlinedButton(onClick = { showUnrootDialog = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }

    installState.unrootWarning?.let { warning ->
        UnrootIncompleteSheet(
            warning = warning,
            onDismiss = onCancelUnrootReboot,
            onRebootAnyway = onRebootAnyway,
        )
    }

    LaunchedEffect(installState.log) {
        delay(40.milliseconds)
        logScrollState.scrollTo(logScrollState.maxValue)
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // Header
        Column(
            modifier = Modifier.padding(top = 28.dp, bottom = 4.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(R.string.install_title),
                style = MaterialTheme.typography.headlineLarge,
            )
            Text(
                text = if (installState.busy) {
                    stringResource(R.string.install_keep_open)
                } else {
                    installState.message
                },
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        // Status card
        InstallerStatusCard(installState)

        // Steps
        InstallerSteps(installState.phase, steps)

        // Log output
        InstallerLog(
            output = installState.log,
            modifier = Modifier.weight(1f),
            scrollState = logScrollState,
        )

        // Action buttons when not busy
        if (!installState.busy) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(bottom = 20.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                when {
                    installState.phase == InstallPhase.Failed -> {
                        FilledTonalButton(
                            onClick = onClose,
                            modifier = Modifier.weight(1f),
                        ) {
                            Text(stringResource(R.string.action_close))
                        }
                        if (installState.retryAllowed) {
                            Button(
                                onClick = onRetry,
                                modifier = Modifier.weight(1f),
                            ) {
                                Text(stringResource(R.string.action_retry))
                            }
                        }
                    }

                    installState.phase == InstallPhase.Installed -> {
                        Column(
                            verticalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Button(
                                onClick = onClose,
                                modifier = Modifier.fillMaxWidth(),
                            ) {
                                Text(stringResource(R.string.action_done))
                            }
                            if (installState.canUnrootCurrentSession) {
                                Button(
                                    onClick = { showUnrootDialog = true },
                                    modifier = Modifier.fillMaxWidth(),
                                    colors = ButtonDefaults.buttonColors(
                                        containerColor = MaterialTheme.colorScheme.error,
                                        contentColor = MaterialTheme.colorScheme.onError,
                                    ),
                                ) {
                                    Icon(
                                        imageVector = Icons.Rounded.DeleteForever,
                                        contentDescription = null,
                                    )
                                    Text(stringResource(R.string.action_unroot))
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

// ── Status Card ───────────────────────────────────────────────────

@Composable
private fun InstallerStatusCard(
    installState: com.alex193a.rootmypixel.domain.model.InstallUiState,
) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .animateContentSize(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(
            containerColor = when (installState.phase) {
                InstallPhase.Failed ->
                    MaterialTheme.colorScheme.errorContainer
                else -> MaterialTheme.colorScheme.primaryContainer
            },
        ),
    ) {
        Column(
            modifier = Modifier.padding(20.dp),
            verticalArrangement = Arrangement.spacedBy(18.dp),
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                AnimatedContent(
                    targetState = installState.phase,
                    label = "status-icon",
                ) { phase ->
                    when {
                        installState.busy -> CircularProgressIndicator(modifier = Modifier.size(44.dp))
                        phase == InstallPhase.Installed ->
                            Icon(Icons.Rounded.Check, contentDescription = null, modifier = Modifier.size(44.dp))
                        else -> Icon(Icons.Rounded.Error, contentDescription = null, modifier = Modifier.size(44.dp))
                    }
                }
                Column(modifier = Modifier.weight(1f)) {
                    Text(text = installState.message, style = MaterialTheme.typography.titleLarge)
                    Text(
                        text = phaseDetail(installState.phase),
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
            LinearProgressIndicator(
                progress = { installProgress(installState.phase) },
                modifier = Modifier.fillMaxWidth(),
                drawStopIndicator = {},
            )
        }
    }
}

// ── Steps list ────────────────────────────────────────────────────

@Composable
private fun InstallerSteps(
    phase: InstallPhase,
    steps: List<InstallerStep>,
) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
        ),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            steps.forEachIndexed { index, step ->
                val stepState = stepState(phase, index)
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(14.dp),
                ) {
                    Surface(
                        modifier = Modifier.size(38.dp),
                        shape = CircleShape,
                        color = if (stepState >= 1) {
                            MaterialTheme.colorScheme.primary
                        } else {
                            MaterialTheme.colorScheme.surfaceContainerHighest
                        },
                        contentColor = if (stepState >= 1) {
                            MaterialTheme.colorScheme.onPrimary
                        } else {
                            MaterialTheme.colorScheme.onSurfaceVariant
                        },
                    ) {
                        Box(contentAlignment = Alignment.Center) {
                            Icon(
                                imageVector = if (stepState == 2) Icons.Rounded.Check else step.icon,
                                contentDescription = null,
                                modifier = Modifier.size(21.dp),
                            )
                        }
                    }
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = stringResource(step.title),
                            style = MaterialTheme.typography.titleSmall
                        )
                        Text(
                            text = stringResource(step.detail),
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                    if (stepState == 1 && phase !in setOf(
                            InstallPhase.Failed,
                            InstallPhase.Ready,
                        )
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp))
                    }
                }
            }
        }
    }
}

// ── Log view ──────────────────────────────────────────────────────

@Composable
private fun InstallerLog(
    output: String,
    modifier: Modifier = Modifier,
    scrollState: androidx.compose.foundation.ScrollState,
) {
    val context = LocalContext.current

    @Suppress("DEPRECATION")
    val clipboardManager = LocalClipboardManager.current

    Card(
        modifier = modifier.fillMaxWidth(),
        shape = MaterialTheme.shapes.large,
    ) {
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = stringResource(R.string.install_live_progress),
                    style = MaterialTheme.typography.titleMedium,
                )
                IconButton(
                    onClick = {
                        clipboardManager.setText(AnnotatedString(output))
                        Toast.makeText(
                            context,
                            R.string.copied_to_clipboard,
                            Toast.LENGTH_SHORT,
                        ).show()
                    },
                    enabled = output.isNotBlank(),
                ) {
                    Icon(
                        imageVector = Icons.Rounded.ContentCopy,
                        contentDescription = stringResource(R.string.action_copy_log),
                    )
                }
            }
            Text(
                text = output.ifBlank { stringResource(R.string.install_preparing) },
                modifier = Modifier
                    .fillMaxWidth()
                    .weight(1f)
                    .verticalScroll(scrollState),
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                lineHeight = 18.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────

@Composable
private fun phaseDetail(phase: InstallPhase): String =
    stringResource(
        when (phase) {
            InstallPhase.Checking -> R.string.phase_checking
            InstallPhase.Ready -> R.string.phase_ready
            InstallPhase.Downloading -> R.string.phase_downloading
            InstallPhase.Exploiting -> R.string.phase_exploiting
            InstallPhase.LoadingKernelSu -> R.string.phase_loading_ksu
            InstallPhase.Installed -> R.string.phase_installed
            InstallPhase.Failed -> R.string.phase_failed
        },
    )

private fun installProgress(phase: InstallPhase): Float =
    when (phase) {
        InstallPhase.Checking -> 0.1f
        InstallPhase.Ready -> 0f
        InstallPhase.Downloading -> 0.33f
        InstallPhase.Exploiting -> 0.66f
        InstallPhase.LoadingKernelSu -> 0.85f
        InstallPhase.Installed -> 1f
        InstallPhase.Failed -> 0f
    }

private fun stepState(
    phase: InstallPhase,
    stepIndex: Int
): Int {
    if (phase == InstallPhase.Installed) return 2
    val activeIndex = when (phase) {
        InstallPhase.Checking,
        InstallPhase.Ready,
        InstallPhase.Failed -> 0

        InstallPhase.Downloading -> 1
        InstallPhase.Exploiting -> 2
        InstallPhase.LoadingKernelSu -> 3
        InstallPhase.Installed -> 4
    }
    return when {
        stepIndex < activeIndex -> 2
        stepIndex == activeIndex -> 1
        else -> 0
    }
}
