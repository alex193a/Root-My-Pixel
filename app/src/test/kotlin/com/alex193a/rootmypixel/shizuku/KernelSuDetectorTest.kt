package com.alex193a.rootmypixel.shizuku

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class KernelSuDetectorTest {

    @Test
    fun `parses kernel version from ksud output`() {
        assertEquals(12, KernelSuDetector.parseKernelVersion("Kernel Version: 12"))
        assertEquals(12, KernelSuDetector.parseKernelVersion("late-load start\nKernel Version: 12\n"))
        assertEquals(12, KernelSuDetector.parseKernelVersion("Kernel Version:12"))
    }

    /** Zero means "ksud answered, module not live" and must not read as null. */
    @Test
    fun `distinguishes a zero version from no answer`() {
        assertEquals(0, KernelSuDetector.parseKernelVersion("Kernel Version: 0"))
        assertEquals(-1, KernelSuDetector.parseKernelVersion("Kernel Version: -1"))
        assertNull(KernelSuDetector.parseKernelVersion(""))
        assertNull(KernelSuDetector.parseKernelVersion("sh: ksud-pixel: not found"))
    }

    @Test
    fun `install guard suppresses probing`() {
        KernelSuDetector.beginInstall()
        try {
            assert(KernelSuDetector.isInstallInFlight())
        } finally {
            KernelSuDetector.endInstall()
        }
        assert(!KernelSuDetector.isInstallInFlight())
    }
}
