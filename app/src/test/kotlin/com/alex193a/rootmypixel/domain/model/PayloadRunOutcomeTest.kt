package com.alex193a.rootmypixel.domain.model

import com.alex193a.rootmypixel.core.Result
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PayloadRunOutcomeTest {
    @Test
    fun parseVersionedRouteDisabled_isTerminal() {
        val parsed = PayloadResultParser.parse(
            "RMP_PAYLOAD_RESULT:v1 run_id=42-1 success=0 retryable=0 " +
                "reason=ROUTE_DISABLED stage=gate attempts=0 cleanup=not_needed",
        )

        assertTrue(parsed is Result.Success)
        val outcome = (parsed as Result.Success).data
        assertFalse(outcome.success)
        assertFalse(outcome.retryable)
        assertEquals(PayloadReason.ROUTE_DISABLED, outcome.reason)
        assertEquals(0, outcome.attempts)
    }

    @Test
    fun parseRun3Fallback_isTerminalAndStripsBrokenAnsi() {
        val parsed = PayloadResultParser.parse(
            "�[32mRUN_END run_id=26075-9825 done=0 reason=ROUTE_DISABLED " +
                "stage=gate attempts=0 pages=0 worker_state=not_started " +
                "cleanup_state=not_needed\nRMP_EXEC_EXIT:0",
        )

        assertTrue(parsed is Result.Success)
        val outcome = (parsed as Result.Success).data
        assertEquals(PayloadReason.ROUTE_DISABLED, outcome.reason)
        assertFalse(outcome.retryable)
    }

    @Test
    fun loaderExitAlone_isNotPayloadSuccess() {
        val parsed = PayloadResultParser.parse("RMP_EXEC_EXIT:0")
        assertEquals(Result.Error(PayloadResultError.MISSING), parsed)
    }

    @Test
    fun legacyPositiveMarkers_remainAvailableToCaller() {
        val log = "pipe-physrw-summary done=1 root=1 kaslr=1"
        val parsed = PayloadResultParser.parse(log)

        assertEquals(Result.Error(PayloadResultError.MISSING), parsed)
        assertTrue(PayloadResultParser.hasLegacySuccessMarkers(log))
    }

    @Test
    fun unknownReason_cannotEnableRetry() {
        val parsed = PayloadResultParser.parse(
            "RMP_PAYLOAD_RESULT:v1 run_id=x success=0 retryable=1 " +
                "reason=FUTURE_REASON stage=gate attempts=0 cleanup=unknown",
        )

        assertTrue(parsed is Result.Success)
        val outcome = (parsed as Result.Success).data
        assertEquals(PayloadReason.UNKNOWN, outcome.reason)
        assertFalse(outcome.retryable)
    }

    @Test
    fun conflictingResults_failClosed() {
        val parsed = PayloadResultParser.parse(
            """
            RMP_PAYLOAD_RESULT:v1 run_id=a success=0 retryable=0 reason=ROUTE_DISABLED stage=gate attempts=0 cleanup=not_needed
            RMP_PAYLOAD_RESULT:v1 run_id=b success=1 retryable=0 reason=OK stage=done attempts=1 cleanup=complete
            """.trimIndent(),
        )
        assertEquals(Result.Error(PayloadResultError.CONFLICTING), parsed)
    }
}
