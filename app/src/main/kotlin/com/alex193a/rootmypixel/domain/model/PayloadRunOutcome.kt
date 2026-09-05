package com.alex193a.rootmypixel.domain.model

import com.alex193a.rootmypixel.core.Error
import com.alex193a.rootmypixel.core.Result

enum class PayloadReason {
    OK,
    ROUTE_DISABLED,
    NO_VERIFIED_ROUTE,
    RESULT_INVALID,
    CLEANUP_INCOMPLETE,
    UNSAFE_STATE,
    SLIDE_VALUE_INVALID,
    CFI_STAGE_FAILED,
    RECLAIM_SYSCALL_FAILED,
    NO_OBSERVED_EFFECT,
    UNKNOWN;

    companion object {
        fun fromWire(value: String): PayloadReason =
            entries.firstOrNull { it.name == value } ?: UNKNOWN
    }
}

data class PayloadRunOutcome(
    val runId: String,
    val success: Boolean,
    val retryable: Boolean,
    val reason: PayloadReason,
    val stage: String,
    val attempts: Int,
    val cleanup: String,
)

enum class PayloadResultError(override val message: String) : Error {
    MISSING("Payload result is missing"),
    MALFORMED("Payload result is malformed"),
    CONFLICTING("Payload emitted conflicting results"),
}

data class PayloadExecutionError(
    override val message: String,
    val retryable: Boolean,
    val reason: PayloadReason? = null,
) : Error

object PayloadResultParser {
    private const val RESULT_PREFIX = "RMP_PAYLOAD_RESULT:v1"
    private const val LEGACY_PREFIX = "RUN_END"
    private val ansiPattern = Regex("(?:\\u001B|\\uFFFD)?\\[[0-9;]*m")
    private val fieldPattern = Regex("([A-Za-z_]+)=([^\\s]+)")

    fun sanitizeForDisplay(raw: String): String = raw.replace(ansiPattern, "")

    fun hasLegacySuccessMarkers(raw: String): Boolean {
        val clean = sanitizeForDisplay(raw)
        return clean.contains("done=1") && clean.contains("root=1")
    }

    fun parse(raw: String): Result<PayloadRunOutcome, PayloadResultError> {
        val clean = sanitizeForDisplay(raw)
        val versioned = clean.lineSequence()
            .map(String::trim)
            .filter { it.startsWith(RESULT_PREFIX) }
            .toList()
        if (versioned.isNotEmpty()) {
            if (versioned.distinct().size != 1) {
                return Result.Error(PayloadResultError.CONFLICTING)
            }
            return parseLine(versioned.last(), legacy = false)
        }

        val legacy = clean.lineSequence()
            .map(String::trim)
            .filter { it.startsWith(LEGACY_PREFIX) }
            .toList()
        if (legacy.isEmpty()) return Result.Error(PayloadResultError.MISSING)
        if (legacy.distinct().size != 1) {
            return Result.Error(PayloadResultError.CONFLICTING)
        }
        return parseLine(legacy.last(), legacy = true)
    }

    private fun parseLine(
        line: String,
        legacy: Boolean,
    ): Result<PayloadRunOutcome, PayloadResultError> {
        val fields = fieldPattern.findAll(line).associate { match ->
            match.groupValues[1] to match.groupValues[2]
        }
        val runId = fields["run_id"]
            ?: return Result.Error(PayloadResultError.MALFORMED)
        val success = parseBoolean(fields[if (legacy) "done" else "success"])
            ?: return Result.Error(PayloadResultError.MALFORMED)
        val reasonValue = fields["reason"]
            ?: return Result.Error(PayloadResultError.MALFORMED)
        val attempts = fields["attempts"]?.toIntOrNull()
            ?: return Result.Error(PayloadResultError.MALFORMED)
        if (attempts < 0) return Result.Error(PayloadResultError.MALFORMED)

        val wireRetryable = if (legacy) false else {
            parseBoolean(fields["retryable"])
                ?: return Result.Error(PayloadResultError.MALFORMED)
        }
        val reason = PayloadReason.fromWire(reasonValue)
        if (success != (reason == PayloadReason.OK)) {
            return Result.Error(PayloadResultError.MALFORMED)
        }
        val stage = fields["stage"]
            ?: return Result.Error(PayloadResultError.MALFORMED)
        val cleanup = fields[if (legacy) "cleanup_state" else "cleanup"]
            ?: return Result.Error(PayloadResultError.MALFORMED)
        val retryable = wireRetryable && reason == PayloadReason.OK
        return Result.Success(
            PayloadRunOutcome(
                runId = runId,
                success = success,
                retryable = retryable,
                reason = reason,
                stage = stage,
                attempts = attempts,
                cleanup = cleanup,
            ),
        )
    }

    private fun parseBoolean(value: String?): Boolean? = when (value) {
        "1" -> true
        "0" -> false
        else -> null
    }
}
