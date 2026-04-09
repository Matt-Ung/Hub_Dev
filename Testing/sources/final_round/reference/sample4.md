# sample4.exe Reference

- Final filename: `sample4.exe`
- Original source sample: `WannaCry`
- Family label (evaluator-side only): `WannaCry simulation`
- Platform / architecture: `windows` / `x86_64`
- Build mode: `release`
- Stripped: `true`
- Packed: `true`
- Final artifact path: `output/sample4.exe`
- SHA256: populated after the final build if you add hashes manually

## Intended Simulation
Ransomware-worm-style sample combining mutex / service persistence, resource extraction attempts, backup deletion, ransom-note display, and multithreaded SMB propagation logic.

## Major Observable Capabilities
- Killswitch-domain HTTP reachability check using WinINet before the main ransomware flow proceeds.
- Single-instance mutex using Global\MsWinZonesCacheCounterMutexA.
- Service installation masquerading as Microsoft Security Center (2.0) Service with service name mssecsvc2.0.
- Extraction attempts for @WanaDecryptor@.exe and related component resources into a hidden temp directory.
- Backup-deletion command execution through vssadmin delete shadows and wmic shadowcopy delete.
- Recursive candidate-file enumeration against the configured target-extension list before ransom-note display.
- Ransom-note-style UI with embedded bitcoin addresses.
- Multithreaded SMB port-445 scanning, random IP generation, and EternalBlue-like packet structure simulation.

## Important Limitations
- No .rc file or embedded resource binaries are checked in, so decryptor / cleanup extraction paths are structurally present but unbacked by repository artifacts.
- The encryption logic itself is not implemented in the checked-in source.
- The worm routine simulates exploit structure and returns success without implementing MS17-010 exploitation.
- Enumeration currently counts candidate files but does not encrypt or rename them.

## Judge-Facing Ground Truth
### Must-Hit Anchors
- Killswitch-domain check to `http://www.example-killswitch.com/` before the main ransomware / worm flow.
- Single-instance mutex `Global\MsWinZonesCacheCounterMutexA` and service-based persistence using `mssecsvc2.0` / `Microsoft Security Center (2.0) Service`.
- Backup-deletion command execution containing `vssadmin delete shadows /all /quiet` and `wmic shadowcopy delete`.
- Ransomware presentation plus worm-like behavior grounded in `@WanaDecryptor@.exe` staging, `EnumerateCandidateFiles()`, `StartWormPropagation()`, or `ExploitEternalBlue()`.

### Supported High-Confidence Claims
- Killswitch reachability gates execution.
- Persistence is service-based rather than Run-key-based.
- The sample models ransomware presentation, backup deletion, and resource extraction attempts.
- The sample also models multithreaded SMB port-445 scanning and EternalBlue-like exploit structure.
- Candidate-file enumeration is implemented before ransom-note display.

### Limitations To Respect
- No `.rc` file or embedded resource binaries are checked in, so decryptor / cleanup extraction paths are structurally present but unbacked by repository artifacts.
- The encryption logic itself is not implemented in the checked-in source.
- The worm routine simulates exploit structure and returns success without implementing MS17-010 exploitation.
- Enumeration currently counts candidate files but does not encrypt or rename them.

### Do Not Overclaim
- Do not claim real file encryption or renaming behavior when the source only enumerates targets.
- Do not claim an actual checked-in decryptor or resource blob exists in the repository.
- Do not describe the SMB routine as a real EternalBlue exploit implementation.

## Static Analysis Reference
### Strings / anchors
- `Global\MsWinZonesCacheCounterMutexA`
- `mssecsvc2.0`
- `Microsoft Security Center (2.0) Service`
- `@WanaDecryptor@.exe`
- `http://www.example-killswitch.com/`
- `vssadmin delete shadows /all /quiet`
- `wmic shadowcopy delete`
- `Ooops, your files have been encrypted!`
- `13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94`

### Encoded config / embedded data
- Bitcoin address list in wannacry_config.h.
- Target extension and excluded-path lists in wannacry_config.h.
- Resource ID constants for encryptor, privilege escalation helper, cleanup helper, and language resources.

### Resources / embedded components
- Resource IDs are defined in wannacry_config.h, but the repository does not include a resource script or embedded component binaries.

### Imports / runtime clues
- Native Win32 C++ sample using service APIs, ShellExecuteW, WinSock SMB-style sockets, and multithreading.
- The source now includes a WinINet killswitch check and recursive target-file enumeration, but still stops short of real encryption.

## Relationship Reference
### Related Files
- Wannacry/wannacry_main.cpp
- Wannacry/wannacry_worm.cpp
- Wannacry/wannacry_config.h

### Config Files
- Wannacry/wannacry_config.h

### Dropped Or Generated Artifacts
- Hidden temp working directory named from GetTickCount().
- @WanaDecryptor@.exe written into the temp directory if the expected resource exists.
- Service registration under mssecsvc2.0.

### Loader Payload Helper Relationships
- wannacry_main.cpp handles mutex, service install, resource extraction, and ransom-note display.
- wannacry_worm.cpp provides the SMB scan / exploit-structure loop.

## Reporting Reference
### Executive Summary Points
- The sample combines ransomware presentation with worm-like SMB propagation behavior.
- Persistence is handled through service installation rather than a Run key.
- Backup deletion commands and ransom-note strings are strong static anchors.
- Resource-based component extraction is intended but unsupported by any checked-in resource blob.

### Expected Functionality Sections
- mutex / single-instance control
- service-based persistence
- resource extraction and staging
- backup deletion and ransom-note behavior
- SMB propagation / exploit structure

### Detection Opportunities
- Service creation for mssecsvc2.0 / Microsoft Security Center (2.0) Service.
- WinINet GET to the placeholder killswitch domain.
- Command execution containing vssadmin delete shadows /all /quiet or wmic shadowcopy delete.
- Ransom-note strings and @WanaDecryptor@.exe path.
- Aggressive outbound TCP 445 scanning.

## Optional Detection Reference
### Candidate Yara Features
- Global\MsWinZonesCacheCounterMutexA
- mssecsvc2.0
- @WanaDecryptor@.exe
- vssadmin delete shadows /all /quiet
- Ooops, your files have been encrypted!

### Candidate Sigma Behaviors
- Service creation for mssecsvc2.0.
- Execution of vssadmin delete shadows or wmic shadowcopy delete.
- Repeated outbound connections to TCP 445 across many hosts.

## Grounding
- `Wannacry/wannacry_main.cpp` :: `WinMain` supports killswitch gate, mutex check, service install, ransom note.
- `Wannacry/wannacry_main.cpp` :: `IsKillSwitchActivated` supports WinINet killswitch check.
- `Wannacry/wannacry_main.cpp` :: `EnumerateCandidateFiles` supports target-extension recursion.
- `Wannacry/wannacry_main.cpp` :: `ExtractAndRunComponents` supports resource extraction, backup deletion command.
- `Wannacry/wannacry_main.cpp` :: `InstallService` supports service-based persistence.
- `Wannacry/wannacry_worm.cpp` :: `IsSMBPortOpen` supports port 445 scan.
- `Wannacry/wannacry_worm.cpp` :: `ExploitEternalBlue` supports EternalBlue-like packet structure simulation.
- `Wannacry/wannacry_worm.cpp` :: `StartWormPropagation` supports multithreaded worm behavior.
