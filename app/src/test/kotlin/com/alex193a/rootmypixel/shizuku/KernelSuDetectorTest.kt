package com.alex193a.rootmypixel.shizuku

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class KernelSuDetectorTest {
    @Test
    fun acceptsSuccessfulRootProbe() {
        assertTrue(
            KernelSuDetector.isRootShellProbeOutput(
                "ROOT_MY_PIXEL_KSU_ACTIVE\n0\n",
            ),
        )
    }

    @Test
    fun rejectsUnprivilegedOrIncompleteProbe() {
        assertFalse(
            KernelSuDetector.isRootShellProbeOutput(
                "ROOT_MY_PIXEL_KSU_ACTIVE\n2000\n",
            ),
        )
        assertFalse(KernelSuDetector.isRootShellProbeOutput("0\n"))
        assertFalse(KernelSuDetector.isRootShellProbeOutput(""))
    }
}
