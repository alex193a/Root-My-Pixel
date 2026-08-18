package com.alex193a.rootmypixel.domain.usecase

import com.alex193a.rootmypixel.core.Result
import android.net.Uri
import com.alex193a.rootmypixel.domain.model.DeviceSnapshot
import com.alex193a.rootmypixel.domain.model.TargetProfile
import com.alex193a.rootmypixel.domain.model.VerifiedPayloads
import com.alex193a.rootmypixel.domain.repository.PayloadError
import com.alex193a.rootmypixel.domain.repository.PayloadRepository
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class UseCasesTest {

    private val fakeProfile = TargetProfile(
        profileId = "test-profile",
        codename = "test",
        kernelRelease = "6.6.0",
        buildDisplay = "BUILD123",
        exploitAsset = "exploits/test.so",
        kmi = "android15-6.6",
    )

    private val fakeRepo = object : PayloadRepository {
        override suspend fun resolveTarget(snapshot: DeviceSnapshot): Result<TargetProfile, PayloadError> {
            return if (snapshot.model == "Pixel Test") {
                Result.Success(fakeProfile)
            } else {
                Result.Error(PayloadError.UnsupportedError("Unsupported"))
            }
        }

        override suspend fun resolveTarget(profileId: String): Result<TargetProfile, PayloadError> {
            return if (profileId == "test-profile") {
                Result.Success(fakeProfile)
            } else {
                Result.Error(PayloadError.UnsupportedError("Not found"))
            }
        }

        override suspend fun extractPayloads(
            profile: TargetProfile,
            onProgress: (String) -> Unit,
        ): Result<VerifiedPayloads, PayloadError> {
            onProgress("Extracting...")
            return Result.Success(
                VerifiedPayloads(
                    exploit = File("/tmp/exploit.so"),
                    kernelSu = File("/tmp/ksud"),
                    kmi = "android15-6.6",
                )
            )
        }

        override suspend fun extractFromBootImage(uri: Uri, onProgress: (String) -> Unit): Result<TargetProfile, PayloadError> {
            return Result.Error(PayloadError.UnsupportedError("Not used in test"))
        }

        override suspend fun loadTargets(): Result<List<TargetProfile>, PayloadError> {
            return Result.Success(listOf(fakeProfile))
        }
    }

    @Test
    fun resolveTargetUseCase_resolvesSuccessfully() = runBlocking {
        val useCase = ResolveTargetUseCase(fakeRepo)
        val snapshot = DeviceSnapshot(
            kernelRelease = "6.6.0",
            kernelVersion = "Linux version 6.6.0",
            buildDisplay = "BUILD123",
            sdkVersion = 35,
            abi = "arm64-v8a",
            pageSize = 4096,
            model = "Pixel Test",
            device = "test",
        )

        val result = useCase(snapshot)
        assertTrue(result is Result.Success)
        assertEquals("test-profile", (result as Result.Success).data.profileId)
    }

    @Test
    fun downloadPayloadsUseCase_extractsSuccessfully() = runBlocking {
        val useCase = DownloadPayloadsUseCase(fakeRepo)
        var progressCalled = false
        val result = useCase(fakeProfile) { progressCalled = true }

        assertTrue(result is Result.Success)
        assertTrue(progressCalled)
    }
}
