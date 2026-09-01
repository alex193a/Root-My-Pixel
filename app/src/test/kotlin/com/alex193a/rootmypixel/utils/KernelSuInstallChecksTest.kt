package com.alex193a.rootmypixel.utils

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class KernelSuInstallChecksTest {

    @Test
    fun `debug info requires a positive KernelSU version`() {
        assertTrue(
            KernelSuInstallChecks.debugInfoShowsActiveKernelSu(
                """
                version: 35040
                full_version: v4.1.0-88dbc786@ReSukiSU
                runtime_mode: late-load
                """.trimIndent(),
            ),
        )
        assertFalse(KernelSuInstallChecks.debugInfoShowsActiveKernelSu("version: 0"))
        assertFalse(KernelSuInstallChecks.debugInfoShowsActiveKernelSu("connection refused"))
    }

    @Test
    fun `proc modules fallback requires the exact kernelsu module`() {
        assertTrue(
            KernelSuInstallChecks.procModulesShowsActiveKernelSu(
                "kernelsu 114688 1 - Live 0x0000000000000000",
            ),
        )
        assertFalse(
            KernelSuInstallChecks.procModulesShowsActiveKernelSu(
                "not_kernelsu 114688 1 - Live 0x0000000000000000",
            ),
        )
    }

    @Test
    fun `trusted ReSukiSU manager signature is parsed from ksud output`() {
        val signature = KernelSuInstallChecks.parseManagerSignature(
            "size: 0x377, hash: d3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64",
        )

        assertEquals(0x377, signature?.size)
        assertTrue(signature != null && KernelSuInstallChecks.isTrustedManagerSignature(signature))
    }

    @Test
    fun `unknown or malformed manager signatures are rejected`() {
        val unknown = KernelSuInstallChecks.parseManagerSignature(
            "size: 887, hash: a3469712b6214462764a1d8d3e5cbe1d6819a0b629791b9f4101867821f1df64",
        )

        assertTrue(unknown != null)
        assertFalse(KernelSuInstallChecks.isTrustedManagerSignature(unknown!!))
        assertNull(KernelSuInstallChecks.parseManagerSignature("signature unavailable"))
    }
}
