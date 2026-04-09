# sample3.exe Reference

- Final filename: `sample3.exe`
- Original source sample: `TrickBot`
- Family label (evaluator-side only): `TrickBot simulation`
- Platform / architecture: `windows` / `x86_64`
- Build mode: `release`
- Stripped: `true`
- Packed: `true`
- Final artifact path: `output/sample3.exe`
- SHA256: populated after the final build if you add hashes manually

## Intended Simulation
Modular banking-trojan-style loader with layered anti-analysis, registry persistence, encrypted C2 seeds, HTTPS module retrieval, and web-inject-oriented post-exploitation hooks.

## Major Observable Capabilities
- Timing-based debugger detection, hardware-breakpoint checks, WMI-based VM detection, NTDLL .text integrity checking, and TLS-callback anti-debug logic.
- In-memory PE-header corruption intended to complicate dumping.
- Registry Run-key persistence using value name WindowsDefender.
- Encrypted C2 server list bytes in config.h decoded before network use.
- HTTPS POST check-in to /ga/ on port 447.
- Downloaded module handling that distinguishes module IDs such as systeminfo and webinjects.
- Built-in module-descriptor dispatch with DJB2-hashed names and XML-style per-module configuration parsing.
- Web-inject setup that writes browser-facing configuration into an Internet Explorer registry location.

## Important Limitations
- The code simulates module retrieval and does not implement a full reflective DLL loader or real TrickBot cryptography.
- GetAntiDebugScript() is present as a reference artifact, but it is not invoked by the main execution path in trick_main.cpp.
- TLS callback registration behavior depends on the Windows toolchain / linker honoring the callback section directives.

## Judge-Facing Ground Truth
### Must-Hit Anchors
- Anti-analysis anchored to `DetectNtdllHooks()`, WMI VM detection, timing or hardware-breakpoint checks, or the TLS callback path.
- Run-key persistence using `Software\Microsoft\Windows\CurrentVersion\Run` with value name `WindowsDefender`.
- Encrypted C2 seed recovery tied to the HTTPS `/ga/` POST path on port `447`.
- Browser-facing staging anchored to `InstallWebInjects()`, bank-target patterns, or the Internet Explorer `AcceptLanguage` registry modification.

### Supported High-Confidence Claims
- Anti-analysis gates execution before persistence or module retrieval.
- In-memory PE-header corruption is used as an anti-dumping complication.
- Registry persistence is implemented.
- HTTPS C2 plus modular follow-on behavior is staged.
- Web-inject intent is represented through target lists and browser-facing registry writes.

### Limitations To Respect
- The code simulates module retrieval and does not implement a full reflective DLL loader or real TrickBot cryptography.
- `GetAntiDebugScript()` is present as a reference artifact but is not invoked by the main execution path in `trick_main.cpp`.
- TLS callback registration behavior depends on the Windows toolchain and linker honoring the callback section directives.

### Do Not Overclaim
- Do not claim live browser hooking or a fully operational webinject stack when only structural target patterns and registry staging are present.
- Do not claim `GetAntiDebugScript()` executes in the main path unless independently grounded elsewhere.
- Do not overstate the network protocol beyond the encrypted server seeds and fixed `/ga/` beacon path.

## Static Analysis Reference
### Strings / anchors
- `Software\Microsoft\Windows\CurrentVersion\Run`
- `WindowsDefender`
- `/ga/`
- `ROOT\CIMV2`
- `SELECT * FROM Win32_ComputerSystem WHERE Model LIKE '%VMware%' OR Model LIKE '%VirtualBox%'`
- `*.bankofamerica.com/*`
- `*.wellsfargo.com/*`
- `*.chase.com/*`
- `*.citi.com/*`
- `Software\Microsoft\Internet Explorer\International`
- `AcceptLanguage`
- `InjectTarget`
- `NetworkExfilUrl`

### Encoded config / embedded data
- ENC_C2_SERVERS byte array in TrickBot/trick_config.h.
- TrickModule enum with module IDs for system info, inject DLL, web injects, network DLL, and bcrypt support.
- Bank-target URL patterns stored in INJECT_TARGETS.

### Resources / embedded components
- No external module blobs or resource files are checked in with this simulation.

### Imports / runtime clues
- Native Win32 C++ sample using WinHTTP, WMI COM interfaces, registry APIs, and low-level thread context / PE structures.
- No browser hooking implementation is shipped; only the structure and target patterns are present.

## Relationship Reference
### Related Files
- TrickBot/trick_main.cpp
- TrickBot/trick_antidebug.cpp
- TrickBot/trick_config.h

### Config Files
- TrickBot/trick_config.h

### Dropped Or Generated Artifacts
- Registry Run value WindowsDefender referencing the current executable.
- Internet Explorer AcceptLanguage registry value under the International key.

### Loader Payload Helper Relationships
- trick_main.cpp handles persistence, C2 traffic, XML-backed module dispatch, and browser-facing staging.
- trick_antidebug.cpp contains debugger, VM, NTDLL hook-detection, PE corruption, and TLS callback routines.
- trick_config.h stores encrypted server bytes and web-inject target patterns.

## Reporting Reference
### Executive Summary Points
- The sample foregrounds anti-analysis before registry persistence or module retrieval.
- Persistence is set through a Run value named WindowsDefender.
- HTTPS C2 traffic is modeled through a /ga/ POST path and encrypted-seed server list.
- Web-inject-style post-exploitation is represented by bank target patterns and browser-related registry changes.

### Expected Functionality Sections
- anti-analysis and anti-debugging
- persistence
- C2 and module retrieval
- web-inject / browser-manipulation intent
- module architecture

### Detection Opportunities
- Registry Run value WindowsDefender in the current-user hive.
- Fixed /ga/ C2 path and port-447 HTTPS usage.
- WMI query strings for VMware / VirtualBox model checks.
- Bank-target wildcard strings that resemble web-inject target lists.

## Optional Detection Reference
### Candidate Yara Features
- WindowsDefender
- /ga/
- *.bankofamerica.com/*
- *.wellsfargo.com/*
- *.chase.com/*
- *.citi.com/*

### Candidate Sigma Behaviors
- Registry Run-key creation with value name WindowsDefender.
- HTTPS connections to high ports such as 447 with a fixed /ga/ path.
- Registry modification of Internet Explorer International\AcceptLanguage.

## Grounding
- `TrickBot/trick_main.cpp` :: `WinMain` supports anti-analysis gating, Run-key persistence, module loop.
- `TrickBot/trick_main.cpp` :: `TrickbotC2Checkin` supports HTTPS POST /ga/, module-response handling.
- `TrickBot/trick_main.cpp` :: `DispatchConfiguredModules` supports DJB2 module hashing, XML-style config parsing, module staging.
- `TrickBot/trick_main.cpp` :: `InstallWebInjects` supports browser-facing registry manipulation.
- `TrickBot/trick_antidebug.cpp` :: `IsVirtualMachine` supports WMI-based VM check.
- `TrickBot/trick_antidebug.cpp` :: `DetectNtdllHooks` supports NTDLL hook / section-hash detection.
- `TrickBot/trick_antidebug.cpp` :: `TlsCallback` supports TLS anti-debug path.
- `TrickBot/trick_antidebug.cpp` :: `CorruptPEHeader` supports in-memory PE corruption.
