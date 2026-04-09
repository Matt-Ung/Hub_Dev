# sample2.exe Reference

- Final filename: `sample2.exe`
- Original source sample: `QakBot`
- Family label (evaluator-side only): `QakBot simulation`
- Platform / architecture: `windows` / `x86_64`
- Build mode: `release`
- Stripped: `true`
- Packed: `true`
- Final artifact path: `output/sample2.exe`
- SHA256: populated after the final build if you add hashes manually

## Intended Simulation
Banking-trojan-style loader with parameter-driven execution paths, scheduled-task persistence, resource-based payload staging, injection, named-pipe coordination, and self-delete logic.

## Major Observable Capabilities
- Command-line-controlled execution branches for install, wait, inject, pipe, and self-delete modes.
- Environment checks against analyst-tool process names plus CPUID hypervisor checks, timing anomalies, and VM-related registry artifacts.
- Single-instance mutex using the Global\QBot_%08X_Session pattern.
- Scheduled-task persistence via Task Scheduler COM APIs with a WindowsUpdateTask_%08X naming scheme.
- Resource-payload extraction / XOR decode path centered on resource ID 307.
- Remote-thread injection into a discovered svchost.exe process.
- Named-pipe server setup under \\.\pipe\qbot_%08X for module coordination.
- Self-delete through a generated cleanup.bat file launched with ShellExecuteW.

## Important Limitations
- The repository does not contain a .rc file or embedded payload resource, so ExtractResourcePayload() is structurally present but unbacked by checked-in artifact data.
- Injection success depends on that extracted payload path producing bytes at runtime.
- The module execution path is simplified and does not implement a full reflective loader.

## Judge-Facing Ground Truth
### Must-Hit Anchors
- Command-line mode branching through install, wait, inject, pipe, or self-delete style flags rather than one linear payload path.
- Scheduled-task persistence named `WindowsUpdateTask_%08X` via Task Scheduler COM.
- Resource-backed payload path centered on `ExtractResourcePayload()` and resource ID `307`, with the missing checked-in blob called out explicitly.
- Concrete follow-on behavior such as `svchost.exe` injection, `\\.\pipe\qbot_%08X` named-pipe setup, or `cleanup.bat` self-delete.

### Supported High-Confidence Claims
- Execution is mode-driven and branches heavily on command-line flags.
- Environment checks include analyst-tool process names, CPUID hypervisor checks, timing anomalies, and VM registry artifacts.
- Scheduled-task persistence is implemented.
- The source models resource-backed payload extraction and subsequent injection into `svchost.exe`.
- Named-pipe coordination and self-delete behavior are implemented.

### Limitations To Respect
- The repository does not contain a `.rc` file or payload blob, so `ExtractResourcePayload()` is structurally present but unbacked by checked-in artifact data.
- Injection success depends on the extracted payload path returning bytes at runtime.
- The module execution path is simplified and does not implement a full reflective loader.

### Do Not Overclaim
- Do not claim that a checked-in resource blob or real staged payload is present in the repository.
- Do not claim a full banking-module ecosystem or reflective loader when only the structural path is implemented.
- Do not describe injection as guaranteed successful independently of the missing resource payload.

## Static Analysis Reference
### Strings / anchors
- `Global\QBot_%08X_Session`
- `WindowsUpdateTask_%08X`
- `\\.\pipe\qbot_%08X`
- `cleanup.bat`
- `svchost.exe`
- `/C`
- `/W`
- `/I`
- `/P`
- `/Q`
- `procmon.exe`
- `wireshark.exe`
- `x64dbg.exe`
- `HARDWARE\ACPI\DSDT\VBOX__`
- `SOFTWARE\VMware Inc.\VMware Tools`

### Encoded config / embedded data
- Resource payload ID 307 in qakbot_config.h.
- Version constants QBOT_MAJOR_VERSION / QBOT_MINOR_VERSION / QBOT_BUILD_TIMESTAMP.
- XOR-based payload decode in ExtractResourcePayload().

### Resources / embedded components
- Resource extraction logic expects a PAYLOAD resource with ID 307, but no resource script or binary blob is checked in.

### Imports / runtime clues
- Native Win32 C++ sample using Task Scheduler COM APIs, Toolhelp process enumeration, ShellExecuteW, named pipes, and remote-thread injection.
- No managed runtime or script interpreter is present.

## Relationship Reference
### Related Files
- Qakbot/qbot_main.cpp
- Qakbot/qbot_utils.cpp
- Qakbot/qakbot_config.h

### Config Files
- Qakbot/qakbot_config.h

### Dropped Or Generated Artifacts
- Scheduled task named WindowsUpdateTask_<tickcount>.
- cleanup.bat self-delete script in the temp directory.
- Named pipe \\.\pipe\qbot_<pid>.

### Loader Payload Helper Relationships
- qbot_main.cpp selects the behavior branch based on command-line switches.
- qbot_utils.cpp implements process, CPUID, timing, and registry environment checks plus scheduled-task persistence, resource extraction, and named-pipe creation.

## Reporting Reference
### Executive Summary Points
- The sample branches heavily on command-line mode flags rather than a single linear execution path.
- Persistence is implemented as a scheduled task masquerading as a Windows update component.
- A resource-backed core payload is expected and then injected into svchost.exe.
- Named-pipe coordination and self-delete logic are present.

### Expected Functionality Sections
- execution modes / command-line handling
- anti-analysis
- scheduled-task persistence
- resource payload staging
- process injection
- named-pipe coordination
- self-delete behavior

### Detection Opportunities
- Task names matching WindowsUpdateTask_* created through Task Scheduler COM.
- Named-pipe pattern \\.\pipe\qbot_*.
- cleanup.bat self-delete batch creation.
- Registry/process blacklist strings for common analyst tools.

## Optional Detection Reference
### Candidate Yara Features
- Global\QBot_%08X_Session
- \\.\pipe\qbot_%08X
- WindowsUpdateTask_%08X
- cleanup.bat

### Candidate Sigma Behaviors
- Scheduled-task creation masquerading as a Windows update component.
- Creation of a named pipe matching \\.\pipe\qbot_*.
- Batch-file-based self-delete behavior.

## Grounding
- `Qakbot/qbot_main.cpp` :: `wWinMain` supports mode flags, mutex, payload branch, self-delete path.
- `Qakbot/qbot_main.cpp` :: `InjectIntoProcess` supports svchost.exe targeting, remote-thread injection.
- `Qakbot/qbot_main.cpp` :: `SetupPipeCommunication` supports named-pipe coordination.
- `Qakbot/qbot_utils.cpp` :: `QbotCheckEnvironment` supports analysis-tool blacklist, CPUID hypervisor check, timing probe, VM registry artifact check.
- `Qakbot/qbot_utils.cpp` :: `InstallScheduledTask` supports scheduled-task persistence.
- `Qakbot/qbot_utils.cpp` :: `ExtractResourcePayload` supports resource-backed payload path, XOR decode.
