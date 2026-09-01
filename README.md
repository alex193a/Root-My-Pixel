# Root My Pixel

**Root My Pixel** is an Android application designed to automate root access on **Google Pixel** devices leveraging the **NebuSec IonStack** exploit (CVE-2026-43499) and integrating **ReSukiSU / KernelSU**.

---

## How the Application Works

Root My Pixel lets you *temporarily* gain root access with ReSukiSU in just one tap.

### Installation Workflow

1. **Device Detection & Profiling**
   - At startup, the app uses native JNI (`NativeProbe`), `/proc/version` queries, and system properties to detect the device codename, kernel version, CPU ABI, memory page size, and build display ID.
   - Via `ResolveTargetUseCase`, it matches the device details against supported target profiles defined in `assets/profiles.json`.

2. **Shizuku Integration**
   - The app uses **Shizuku** (UID 2000) to acquire ADB shell privileges without needing initial root access, which is required to stage and execute payload binaries in `/data/local/tmp`.
   - A managed `ExploitService` is bound via Binder IPC to stream exploit execution logs to the UI in real time.

3. **Exploit Payload Extraction & Execution**
   - Precompiled binary payloads (`.so`) corresponding to each supported build and the native helper tool (`libcve43499root.so`) are extracted from APK assets to `/data/local/tmp`.
   - The IonStack exploit (CVE-2026-43499) is executed to establish a local root daemon socket (`temp_su.sock`), acquiring full `root` privileges.

4. **KernelSU / ReSukiSU Integration**
   - Staging of the `ksud` binary matching the device's Kernel Module Interface (KMI, e.g., `android15-6.6`).
   - The app triggers the KernelSU **late-load** mechanism (`ksud late-load --kmi <kmi>`).
   - Verifies KernelSU through its UAPI, with `ksud debug info` and `/proc/modules` as compatibility fallbacks.
   - Registers the installed ReSukiSU Manager only after validating its production APK signature.

5. **User Interface & Management Tools**
   - Real-time live log progress monitoring.
   - Handy actions for **Soft Reboot** (restarting `system_server`) and **Log Exporting** for debugging purposes.

---

## Supported Devices & Build Profiles

| Device                | Codename   | Supported Builds   | Kernel KMI      | Tested |
|:----------------------|:-----------|:------------------|:----------------|:--------|
| **Pixel 10**          | `frankel`  | `CP2A.260705.006` | `android15-6.6` | ✅      |
| **Pixel 10 Pro**      | `blazer`   | `CP2A.260705.006` | `android15-6.6` | ✅      |
| **Pixel 10 Pro XL**   | `mustang`  | `CP2A.260705.006` | `android15-6.6` | ✅      |
| **Pixel 10 Pro Fold** | `rango`    | `CP2A.260705.006` | `android15-6.6` | ✅      |
| **Pixel 10a**         | `stallion` | `CP2A.260705.006`<br>`CP2A.260805.005` | `android14-6.1` | ✅      |
| **Pixel 9 Pro Fold**  | `comet`    | `CP2A.260705.006` | `android15-6.1` | ✅      |
| **Pixel 9 Pro**       | `caiman`   | `CP2A.260705.006` | `android15-6.1` | ✅      |
| **Pixel 9 Pro XL**    | `komodo`   | `CP2A.260705.006` | `android15-6.1` | ✅      |
| **Pixel 9**           | `tokay`    | `CP2A.260705.006` | `android14-6.1` | ✅      |
| **Pixel 9a**          | `tegu`     | `CP2A.260705.006` | `android14-6.1` | ✅      |
| **Pixel 8 Pro**       | `husky`    | `CP2A.260705.006` | `android14-6.1` | ✅      |
| **Pixel 8**           | `shiba`    | `CP2A.260705.006` | `android14-6.1` | ✅      |
| **Pixel 8a**          | `akita`    | `CP2A.260805.005` | `android14-6.1` | ✅      |
| **Pixel 7a**          | `lynx`     | `CP2A.260705.006` | `android14-6.1` | ✅      |
| **Pixel 7 Pro**       | `cheetah`  | `CP2A.260705.006` | `android14-6.1` | ✅      |
| **Pixel 7**           | `panther`  | `CP2A.260705.006`<br>`BP2A.250705.008` | `android14-6.1` | ✅      |
| **Pixel 6a**          | `bluejay`  | `CP2A.260705.006`<br>`CP1A.260405.005` | `android14-6.1` | ✅      |
| **Pixel 6**           | `oriole`   | `CP2A.260705.006` | `android14-6.1` | ✅      |
| **Pixel 6 Pro**       | `raven`    | `CP2A.260705.006` | `android14-6.1` | ✅      |
| **Pixel Tablet**      | `tangorpro`| `BP1A.250405.007` | `android14-6.1` | ✅      |

---

## Prerequisites

1. A supported Google Pixel device listed in the table above.
2. **Shizuku** installed and running via ADB (`adb shell sh /sdcard/Android/data/rikka.shizuku/starter.sh` or Wireless Debugging).
3. **ReSukiSU Manager** installed on the device to manage root permissions granted to apps.

---

## Building from Source

To compile the entire project (native helper, exploit payloads for all targets, and the final debug APK):

### Build Requirements
- Android NDK r25+ (`ANDROID_NDK_HOME` set or present in Android SDK)
- macOS (arm64/x86_64) or Linux (x86_64) host
- Java 17+ and Gradle Wrapper

### Build Command
```bash
./build-all.sh
```

The compiled APK will be generated at:
`app/build/outputs/apk/debug/app-debug.apk`

To install it on a connected device via ADB:
```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

⚠️ Keep in mind that the exploit does not have a 100% success rate. Many users have had to try more than 20 times. Many report higher success by opening the app immediately after a reboot, while others find better results 10–40 minutes after rebooting.

---

## Credits

- Exploit: [NebuSec IonStack](https://github.com/NebuSec/CyberMeowfia)
- App architecture: Inspired and adapted from [Root My Galaxy](https://github.com/BuSung-dev/Root-My-Galaxy)
- ReSukiSU (https://github.com/ReSukiSU/ReSukiSU)
