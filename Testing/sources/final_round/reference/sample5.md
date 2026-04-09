# sample5.exe Reference

- Final filename: `sample5.exe`
- Original source sample: `PlugX`
- Family label (evaluator-side only): `PlugX simulation`
- Platform / architecture: `windows` / `x86_64`
- Build mode: `release`
- Stripped: `true`
- Packed: `true`
- Final artifact path: `output/sample5.exe`
- SHA256: populated after the final build if you add hashes manually

## Intended Simulation
PlugX-style RAT / sideloading scenario with registry persistence, config decryption, encrypted runtime-profile staging, keylogging, screenshot capture, structured TCP beaconing, plugin dispatch, and a DLL-entry-oriented execution model exposed through an EXE wrapper.

## Major Observable Capabilities
- Registry Run-key persistence using value name Windows Security Monitor.
- Configuration-decryption routine over an encrypted config blob.
- XOR-decoded runtime profile that supplies C2 endpoints, campaign identifier, interval, and mutex name.
- Single-instance mutex based on the decoded runtime profile.
- Allocated shellcode-execution path backed by an embedded shellcode array.
- Keylogger thread writing a hidden temp file named system.cache.
- Screen-capture routine using GDI bitmap APIs.
- Custom TCP heartbeat packet with magic 0x504C5558 and base64-encoded host metadata payload.
- Plugin dispatch table for screenshot, keylog, and file-manager-style command handling.
- DLL-entry-driven execution model that simulates a sideloaded DLL while still exposing a WinMain wrapper for EXE builds.

## Important Limitations
- plugx_shellcode.c intentionally contains a deterministic one-byte ret stub rather than full shellcode so the sample remains portable and reproducible.
- The final-round workflow emits a single EXE artifact, not a DLL + signed-loader pair.
- The legacy binary config path is still skeletal; the richer operator-facing data lives in the XOR-decoded runtime profile rather than a true loader-side plugin ecosystem.
- Command handlers remain bounded stubs and do not implement a full reverse shell or remote file-management stack.

## Judge-Facing Ground Truth
### Must-Hit Anchors
- Run-key persistence using `Software\Microsoft\Windows\CurrentVersion\Run` with value name `Windows Security Monitor`.
- Configuration or XOR runtime-profile recovery tied to `LoadRuntimeProfile()`, decoded C2 endpoints, interval, mutex, or campaign data.
- Custom TCP beaconing anchored to the `PLUX` magic `0x504C5558` header and plugin-dispatch path.
- Operator-facing behavior such as `system.cache` keylogging, `CaptureScreen()`, or the bounded shellcode path in `plugx_shellcode.c`.

### Supported High-Confidence Claims
- The sample is best described as a PlugX-style RAT / sideloading simulation, not a generic downloader.
- Run-key persistence is implemented.
- Encrypted config plus XOR runtime-profile decoding is implemented.
- Heartbeat framing, plugin dispatch, keylogging, and screenshot capture are implemented in bounded form.
- Execution pivots through `DllMain`-style logic even though the final deliverable is an EXE wrapper.

### Limitations To Respect
- `plugx_shellcode.c` intentionally contains a deterministic one-byte `ret` stub rather than full shellcode so the sample remains portable and reproducible.
- The final-round workflow emits a single EXE artifact, not a DLL plus signed-loader pair.
- The legacy binary config path is skeletal; the richer operator-facing data lives in the XOR-decoded runtime profile.
- Command handlers remain bounded stubs and do not implement a full reverse shell or remote file-management stack.

### Do Not Overclaim
- Do not claim a full sideloading package or DLL-loader pair is present in the final artifact set.
- Do not describe the shellcode path as a full implant; it is intentionally stubbed.
- Do not overstate the plugin handlers as a complete remote shell or file-management ecosystem.

## Static Analysis Reference
### Strings / anchors
- `Software\Microsoft\Windows\CurrentVersion\Run`
- `Windows Security Monitor`
- `system.cache`
- `plugx_filemgr.txt`
- `PLUGIN_KEYLOG|`
- `screenshot`

### Encoded config / embedded data
- ENC_CONFIG byte array in Plugx/plugx_config.h.
- ENC_RUNTIME_PROFILE XOR blob in Plugx/plugx_main.cpp.
- PLUGX_CONFIG structure with magic, beacon interval, port, C2 server, and campaign identifier fields.
- ShellcodeEntry stub and ShellcodeSize in plugx_shellcode.c.

### Resources / embedded components
- No external resource file is present; the shellcode relationship is represented by the checked-in plugx_shellcode.c stub.

### Imports / runtime clues
- Native Win32 C++ sample using WinSock, GDI, keyboard state polling, temp-file logging, and Run-key persistence.
- Execution pivots through DllMain-style logic even when launched as an EXE.

## Relationship Reference
### Related Files
- Plugx/plugx_main.cpp
- Plugx/plugx_shellcode.c
- Plugx/plugx_config.h

### Config Files
- Plugx/plugx_config.h

### Dropped Or Generated Artifacts
- Registry Run value Windows Security Monitor.
- Hidden temp log file named system.cache.
- plugx_filemgr.txt staging file in the temp directory when the file-manager plugin path is exercised.
- In-memory screenshot buffer sent over the beacon socket when commanded.

### Loader Payload Helper Relationships
- plugx_main.cpp drives persistence, runtime-profile decode, keylogging, screenshot capture, plugin dispatch, beaconing, and DllMain/WinMain entry paths.
- plugx_shellcode.c provides the deterministic embedded shellcode stub used by ExecutePlugXShellcode().
- plugx_config.h defines the encrypted configuration structure and registry constants.

## Reporting Reference
### Executive Summary Points
- The sample is better framed as a PlugX-style RAT / sideloading simulation than as a pure standalone downloader.
- Persistence is a Run value named Windows Security Monitor.
- Static anchors include system.cache, the XOR runtime-profile blob, and the PLUGX heartbeat / plugin structures.
- The shellcode path is intentionally stubbed for portability and should be reported as such rather than overclaimed as a full implant.

### Expected Functionality Sections
- persistence
- config decryption
- shellcode / staged execution
- keylogging
- screen capture
- C2 beaconing
- DLL sideloading relationship

### Detection Opportunities
- Run-key persistence with value name Windows Security Monitor.
- Hidden temp-file writes to system.cache.
- Custom outbound TCP beacons with the PLUX / 0x504C5558 heartbeat header.
- Simultaneous keyboard polling and screenshot capture logic.

## Optional Detection Reference
### Candidate Yara Features
- Windows Security Monitor
- system.cache
- PLUGIN_KEYLOG|
- Global\PlugXSim_001

### Candidate Sigma Behaviors
- Registry Run-key creation with value name Windows Security Monitor.
- Hidden temp-file creation or append to system.cache.
- Repeated outbound TCP beacons carrying a PLUX-style header.

## Grounding
- `Plugx/plugx_main.cpp` :: `InstallPersistence` supports Run-key persistence.
- `Plugx/plugx_main.cpp` :: `DecryptConfig` supports encrypted config structure.
- `Plugx/plugx_main.cpp` :: `LoadRuntimeProfile` supports XOR runtime profile, decoded C2 list / mutex / campaign.
- `Plugx/plugx_main.cpp` :: `ExecutePlugXShellcode` supports shellcode allocation/execution path.
- `Plugx/plugx_main.cpp` :: `KeyloggerThread` supports hidden temp log file, keystroke capture.
- `Plugx/plugx_main.cpp` :: `CaptureScreen` supports screenshot logic.
- `Plugx/plugx_main.cpp` :: `C2Beacon` supports PLUX heartbeat protocol, socket C2 path.
- `Plugx/plugx_main.cpp` :: `DispatchPluginCommand` supports plugin dispatch table.
- `Plugx/plugx_shellcode.c` :: `ShellcodeEntry` supports deterministic shellcode stub.
