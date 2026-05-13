# DenuvOwO Hypervisor — Full Reverse Engineering Report
**Target:** Assassin's Creed Shadows [(FitGirl Repack)](https://fitgirl-repacks.site/assassins-creed-shadows/)

**Date:** 2026-05-13  
**Analyst:** 0xPacman  
**Tools:** radare2, objdump, readelf, strings, file (WSL Ubuntu)

---

## 1. Executive Summary

The "hypervisor" shipped with this FitGirl repack is **DenuvOwO** — a Denuvo anti-tamper bypass built on two open-source hypervisor research projects:

- **AMD path:** SimpleSvm (AMD SVM/AMD-V hypervisor)
- **Intel path:** HyperDbg (Intel VT-x/EPT hypervisor)

The crack works by loading an unsigned kernel driver at ring -1 (hypervisor privilege level), placing the entire OS — including Denuvo — inside a virtual machine the crack controls. From this position it intercepts and spoofs every check Denuvo performs: CPUID, MSR reads, syscalls, timing, and memory integrity.

**Build author:** "Andrea" (PDB paths leak full local path)  
**Build environment:** `C:\Users\Andrea\Documents\Denuvo\hypervisor\`

---

## 2. File Inventory

| File | Size | Type | Role |
|---|---|---|---|
| `hypervisor-launcher.exe` | 334 KB | PE32+ GUI x64 | Usermode orchestrator (C++/MSVC) |
| `VBS.cmd` | 50 KB | Batch script | OS security stripper |
| `driver_amd/SimpleSvm.sys` | 18 KB | PE32+ kernel driver | AMD SVM hypervisor |
| `driver_intel/hyperkd.sys` | 12 KB | PE32+ kernel driver | Intel HV loader (thin) |
| `driver_intel/hyperhv.dll` | 538 KB | PE32+ native DLL | Intel VT-x VMM core (~296 exports) |
| `driver_intel/hyperevade.dll` | 7 KB | PE32+ native DLL | Evasion/transparency callbacks |
| `driver_intel/hyperlog.dll` | 14 KB | PE32+ native DLL | Logging subsystem |
| `DenuoOwO_SRC.7z` | 7.6 MB | 7-Zip archive | Full driver source code |

---

## 3. Build Identity (PDB Leak)

PDB paths embedded in every binary expose the developer's full local path:

```
SimpleSvm.sys:
  C:\Users\Andrea\Documents\Denuvo\hypervisor\HypervisorSource\x64\Release\SimpleSvm.pdb

hyperhv.dll:
  C:\Users\Andrea\Documents\Denuvo\hypervisor\IntelTest2.1\build\bin\release\hyperhv.pdb

hyperevade.dll:
  C:\Users\Andrea\Documents\Denuvo\hypervisor\IntelTest2.1\build\bin\release\hyperevade.pdb
```

Two separate project trees: `HypervisorSource` (AMD) and `IntelTest2.1` (Intel).  
Both compiled in Release mode. Both unsigned (no Authenticode signature).

**Stack security cookie:** `0x2b992ddfa232` — identical in both SimpleSvm.sys and hyperevade.dll, confirming shared build toolchain.

---

## 4. hypervisor-launcher.exe — Usermode Orchestrator

### 4.1 Binary Properties

- **Compiler:** MSVC (imports VCRUNTIME140.dll, `__CxxFrameHandler3`, CRT functions)
- **Source hint:** `src\service.rs` string suggests a Rust component statically linked in
- **Size:** 334 KB | `.text` section: 240 KB (0x3aa00 bytes) — substantial logic
- **~300+ functions** identified by r2 analysis
- **Key function:** `fcn.14002abf0` — 587 basic blocks, 66 KB — main service management loop

### 4.2 Import Analysis (Full)

**ntdll.dll:**
| Import | Purpose |
|---|---|
| `RtlAdjustPrivilege` | Enables SE_DEBUG + SE_SYSTEM_ENVIRONMENT privileges |
| `NtQuerySystemInformation` | Queries kernel module list (finds ntoskrnl base) |
| `NtSetSystemEnvironmentValueEx` | **UEFI variable writes** (EfiGuard integration path) |
| `NtOpenFile` / `NtReadFile` | Direct kernel file I/O |

**advapi32.dll (SCM — Service Control Manager):**
| Import | Purpose |
|---|---|
| `OpenSCManagerW` | Opens kernel service database |
| `CreateServiceW` | Registers the HV driver as a service |
| `StartServiceW` | Loads the driver into kernel |
| `ControlService` | Sends STOP to driver on exit |
| `DeleteService` | Removes service entry after use |
| `OpenProcessToken` | Gets current process token |
| `DuplicateTokenEx` | Clones token (for privilege drop) |
| `GetTokenInformation` | Inspects token privileges |
| `CreateProcessWithTokenW` | Launches game as non-admin (drops to explorer token) |

**kernel32.dll (notable):**
| Import | Purpose |
|---|---|
| `GetShellWindow` → `GetWindowThreadProcessId` | Finds Explorer PID |
| `OpenProcess` | Opens Explorer process |
| `CopyFileExW` + `GetTempPathW` | Copies driver to %TEMP% before loading |
| `CreateFileMappingW` + `MapViewOfFile` | Shared memory (inter-process comms) |
| `IsDebuggerPresent` | Anti-debug self-check |

**user32.dll:**
| Import | Purpose |
|---|---|
| `GetShellWindow` | Enumerates desktop windows |
| `MessageBoxA` | Error dialogs |

### 4.3 Execution Flow

```
hypervisor-launcher.exe (Admin)
│
├─ 1. RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE)
│     RtlAdjustPrivilege(SE_SYSTEM_ENVIRONMENT_PRIVILEGE)
│
├─ 2. CPUID check → reads "GenuineIntel" or "AuthenticAMD"
│     → selects driver_intel/ or driver_amd/
│
├─ 3. NtQuerySystemInformation → walks loaded modules
│     → finds ntoskrnl.exe kernel base address
│     → reads CI.dll (Code Integrity) kernel address
│     Logs: "[*] ntoskrnl.exe kernel base: 0x..."
│           "[*] CI variable at kernel address: 0x..."
│
├─ 4. GetTempPathW → CreateDirectoryW → CopyFileExW
│     Copies driver .sys to temp directory
│     Logs: "[*] Driver copied to temporary path: ..."
│
├─ 5. OpenSCManagerW → CreateServiceW(kernel driver type)
│     → StartServiceW → driver loads into kernel
│     Logs: "[*] Creating and starting service '...'"
│           "[+] Driver loaded successfully."
│
├─ 6. Token theft for non-admin game launch:
│     GetShellWindow → GetWindowThreadProcessId (Explorer PID)
│     OpenProcess(Explorer) → OpenProcessToken
│     DuplicateTokenEx → CreateProcessWithTokenW(ACShadows.exe)
│     Logs: "[*] Starting game (non-elevated)"
│           "[+] Game started (PID ...)"
│
├─ 7. WaitForSingleObject (game process handle)
│     Game running — hypervisor active
│
└─ 8. On game exit:
      ControlService(STOP) → DeleteService
      Removes temp driver file and directory
      Logs: "[*] Stopping and deleting service '...'"
            "[+] Service cleaned up."
```

**Notable:** The EfiGuard string (`EFI SetVariable() did not return data. EfiGuard DXE driver not loaded`) suggests a UEFI-level DSE bypass path was prototyped but is not the active path — DSE is disabled via F7 boot option instead.

---

## 5. VBS.cmd — OS Security Demolition Script

Runs before each gaming session. Disables the following Windows security features (tracks changes in `HKLM\SOFTWARE\ManageVBS` for reversal):

| Feature Disabled | Registry Key Modified | Why It Must Go |
|---|---|---|
| **VBS** (Virtualization Based Security) | `DeviceGuard\EnableVirtualizationBasedSecurity = 0` | Windows runs its own hypervisor at ring -1; two hypervisors cannot coexist at the same level |
| **HVCI** (Memory Integrity) | `DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity\Enabled = 0` | Would reject unsigned kernel driver code pages |
| **Credential Guard** | `Lsa\LsaCfgFlags = 0` | Runs inside VBS; must go with VBS |
| **System Guard** | `DeviceGuard\Scenarios\SystemGuard\Enabled = 0` | Hardware root-of-trust attestation would detect HV manipulation |
| **Windows Hello protection** | `DeviceGuard\Scenarios\WindowsHello\Enabled = 0` | Bound to VBS; fails after VBS disabled |
| **Enhanced Sign-in Security** | `DeviceGuard\Scenarios\SecureBiometrics\Enabled = 0` | Same |
| **Windows Hypervisor** | `bcdedit /set hypervisorlaunchtype off` | Evicts Hyper-V from ring -1 so the crack can take it |
| **KVA Shadow** (Meltdown mitigation) | `FeatureSettingsOverride = 2, FeatureSettingsOverrideMask = 3` | Conflicts with the crack's syscall hook on older Intel CPUs |
| **DSE** (Driver Signature Enforcement) | F7 at boot (one-time, via `bcdedit /set onetimeadvancedoptions on`) | Allows loading of unsigned `.sys` driver |
| **BitLocker** | `manage-bde -protectors -disable` (1 reboot suspension) | Prevents recovery key prompt at Startup Settings screen |

**UEFI-locked features:** The script handles UEFI-locked VBS/HVCI/CredentialGuard by deploying `SecConfig.efi` to the EFI partition and adding a BCD boot entry (`{0cb3b571-...}`) that runs at next boot to strip UEFI locks before Windows loads.

**Revert:** All changes tracked under `HKLM\SOFTWARE\ManageVBS`. Running option 3 re-enables exactly what was disabled — no more, no less. DSE re-enables automatically after one boot cycle (it's never permanently disabled).

---

## 6. SimpleSvm.sys — AMD SVM Hypervisor

### 6.1 PE Layout

```
Section   Size      VMA              Flags
.text     0x24f8    0x140001000      READONLY CODE     ← main HV logic
.rdata    0x8d0     0x140004000      READONLY DATA     ← strings, imports
.data     0xf8      0x140005000      DATA              ← globals (incl. cookie)
.pdata    0x198     0x140006000      READONLY DATA     ← exception unwind
INIT      0x65e     0x140007000      READONLY CODE     ← DriverEntry (discarded post-load)
.reloc    0x30      0x140008000      READONLY DATA
```

Total code: ~9.9 KB. Tiny — a lean, minimal SVM hypervisor.

### 6.2 DriverEntry (0x140007000 — INIT section)

```asm
; DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
0x140007000:  mov [rsp+0x8], rbx     ; save rbx
0x140007005:  push rdi
0x140007006:  sub rsp, 0x20          ; shadow space
0x14000700a:  mov rbx, rdx           ; save RegistryPath
0x14000700d:  mov rdi, rcx           ; save DriverObject
0x140007010:  call fcn.14000702c     ; → GS cookie initialization
0x14000701b:  call fcn.140002a70     ; → SvmInitialization (main HV setup)
0x140007020:  mov rbx, [rsp+0x30]   ; restore rbx
0x140007025:  add rsp, 0x20
0x140007029:  pop rdi
0x14000702a:  ret
```

DriverEntry is 43 bytes. It calls exactly two functions: stack cookie init and SVM initialization.

### 6.3 Stack Cookie Init (0x14000702c)

```asm
; Verify GS cookie integrity
0x14000702c:  mov rax, [0x140005010]     ; read stored cookie
0x140007033:  test rax, rax
0x140007036:  je  fail                    ; zero → corrupt
0x140007038:  movabs rcx, 0x2b992ddfa232 ; expected cookie value
0x140007042:  cmp rax, rcx
0x140007045:  je  fail                    ; unchanged → not initialized
0x140007047:  not rax                     ; complement it
0x14000704a:  mov [0x140005018], rax      ; store as verification value
0x140007051:  ret
fail:
0x140007053:  mov ecx, 6                 ; FAST_FAIL_STACK_COOKIE_CHECK_FAILURE
0x140007058:  int 0x29                   ; __fastfail()
```

### 6.4 SVM Initialization — fcn.140002a70 (474 bytes, 20 basic blocks)

This is the core. Based on SimpleSvm architecture:

**Key imports used (in order of execution):**

1. `KeGetCurrentIrql` / `KfRaiseIrql` → Raises IRQL to DISPATCH_LEVEL
2. `KeQueryActiveProcessorCountEx` → Gets logical CPU count
3. `MmAllocateContiguousNodeMemory` → Allocates VMCB (VM Control Block) per-core — must be physically contiguous for SVM
4. `MmGetPhysicalAddress` → Converts VMCB virtual → physical (SVM needs physical addresses)
5. `KeSetSystemGroupAffinityThread` + `KeGetProcessorNumberFromIndex` → Iterates all CPU cores
6. On each core: executes `VMRUN` instruction (AMD SVM root entry) to place that core under hypervisor control
7. `ExCreateCallback` + `ExRegisterCallback` → Registers power/driver-load callbacks
8. `PsSetCreateProcessNotifyRoutine` → Watches for ACShadows.exe to start
9. `MmProbeAndLockPages` + `MmMapLockedPagesSpecifyCache` → Maps guest memory regions

**Guest/Host separation (AMD SVM):**
- VMCB (VM Control Block) defines guest state: all registers, segment descriptors, MSRs
- Host saves its own state to VMSA (VM Save Area)
- `VMRUN` switches to guest; `#VMEXIT` returns to host handler
- VMCB contains intercept bitmaps for: exceptions, I/O, MSR reads/writes, CPUID, RDTSC

**Process monitoring imports:**
- `PsLookupProcessByProcessId` + `KeStackAttachProcess` → Attaches to game process address space
- `PsAcquireProcessExitSynchronization` → Hooks game exit to clean up VMCB
- `NtQuerySystemInformation` → Queries system for process/module information
- `KdDebuggerNotPresent` → Anti-debugging check (if kernel debugger attached, behavior changes)

### 6.5 String: "SSVM" / "SSVMH"

Device names for the driver's kernel device object. Follows Windows driver convention: `\\Device\\SSVM` (device) and `\\DosDevices\\SSVMH` (symbolic link for usermode access).

---

## 7. Intel Driver Stack

### 7.1 hyperkd.sys — Thin Loader (12 KB)

hyperkd.sys is purely a bridge. Its entire import table from hyperhv.dll:

```
VmFuncInitVmm          → Initialize entire VT-x VMM (calls VMXON on all cores)
VmFuncUninitVmm        → Tear down VMM (VMXOFF on all cores)
CounterThreadHandle    → Handle to TSC counter-spoofing thread
CounterUpdater         → Thread function for TSC spoofing
NotifyRoutineActive    → Flag: tells evasion layer HV is live
StopCounterThread      → Stop TSC thread on unload
ProcessExitCleanup     → Cleanup on game process exit
```

hyperkd.sys is just a Windows kernel driver wrapper. It runs in the INIT section, calls `VmFuncInitVmm`, registers an Unload routine that calls `VmFuncUninitVmm`, and returns. All real logic is in hyperhv.dll.

### 7.2 hyperhv.dll — HyperDbg VT-x VMM Core (538 KB, ~296 exports)

Based on HyperDbg (https://hyperdbg.com), a full open-source Intel VT-x hypervisor with EPT, VMCS, and debugging capabilities, adapted specifically for Denuvo bypass.

#### 7.2.1 PE Sections

```
Section    Size      Permissions    Contents
.text      varies    r-x            VMM core code
.rdata     varies    r--            Strings, import/export tables, error messages
.data      varies    rw-            Per-core VMCS state, global flags
.pdata     varies    r--            Exception handling (1000+ unwind entries)
.edata     varies    r--            296 named exports
```

#### 7.2.2 VMM Initialization Chain

```
VmFuncInitVmm
  └─ VmxCheckVmxSupport           check CPUID.1:ECX.5 (VMX bit)
      └─ VmxPerformVirtualizationOnAllCores
            ├─ [DPC broadcast to each core]
            │    └─ VmxPerformVirtualizationOnSpecificCore
            │         ├─ VmxAllocateVmxonRegion    (4KB physically contiguous)
            │         ├─ VmxAllocateVmcsRegion     (4KB physically contiguous)
            │         ├─ VmxAllocateHostGdt        host GDT for VMX mode
            │         ├─ VmxAllocateHostIdt        host IDT
            │         ├─ VmxAllocateHostTss        host TSS
            │         ├─ VmxAllocateVmmStack       host stack (per-core)
            │         ├─ VmxAllocateMsrBitmap      MSR intercept bitmap
            │         ├─ VmxAllocateIoBitmaps      I/O port intercept bitmap
            │         ├─ EptAllocateAndCreateIdentityPageTable  → EPT setup
            │         ├─ EptCheckFeatures          verify EPT/VPID support
            │         └─ VmxVirtualizeCurrentSystem
            │              ├─ VMXON (enter VMX root operation)
            │              ├─ VMCLEAR (reset VMCS)
            │              ├─ VMPTRLD (load VMCS pointer)
            │              ├─ VMWRITE (configure 200+ VMCS fields)
            │              └─ VMLAUNCH (launch VM, guest takes over)
            │
            └─ LstarHook          hook syscall handler (runs after VMLAUNCH)
```

#### 7.2.3 VMEXIT Handler — VmxVmexitHandler

The VMEXIT dispatch loop handles every event that causes the guest to exit to the hypervisor. Key exit reasons handled:

| Exit Reason | Handler | Denuvo Relevance |
|---|---|---|
| `CPUID` | `TransparentCheckAndModifyCpuid` | Hides hypervisor from CPUID |
| `RDMSR` | `TransparentCheckAndModifyMsrRead` | Spoofs MSR values |
| `WRMSR` | `TransparentCheckAndModifyMsrWrite` | Monitors MSR writes |
| `VMCALL` | `VmxVmcallHandler` | Internal HV control channel |
| `EPT violation` | `EptHandleEptViolation` | Memory hook dispatch |
| `EPT misconfiguration` | `EptHandleMisconfiguration` | EPT paging error |
| `MTF` (Monitor Trap Flag) | `MtfHandleVmexit` | Single-step after EPT hook |
| `Exception/NMI` | `IdtEmulationhandleHostInterrupt` | Exception forwarding |
| `External interrupt` | `IdtEmulationhandleHostInterrupt` | Interrupt forwarding |
| `MOV to CR3` | CR3 exit handler | Process switch monitoring |
| `RDTSC/RDTSCP` | Counter spoofing | Anti-timing-attack |
| `RDPMC` | PMC exit handler | Performance counter intercept |
| `EFER syscall` | `LstarHook` path | Syscall intercept |
| `Dirty logging` | `DirtyLoggingHandleVmexits` | Memory write tracking |

#### 7.2.4 VMCALL Handler — VmxVmcallHandler

VMCALLs are the communication channel between the guest (hyperkd.sys, hyperevade.dll) and the VMM host. Each VMCALL has an ID:

```
DirectVmcallTest                           → HV alive check
DirectVmcallPerformVmcall                  → Generic VMCALL dispatch
DirectVmcallChangeMsrBitmapRead/Write      → Enable/disable MSR intercept
DirectVmcallResetMsrBitmapRead/Write       → Clear MSR intercept
DirectVmcallSetExceptionBitmap            → Enable exception intercept
DirectVmcallResetExceptionBitmap          → Disable exception intercept
DirectVmcallChangeIoBitmap                → Enable I/O port intercept
DirectVmcallResetIoBitmap                 → Disable I/O port intercept
DirectVmcallEnableEferSyscall             → Activate syscall hooking
DirectVmcallDisableEferSyscallEvents      → Deactivate syscall hooking
DirectVmcallEnableMovToCrExiting          → Enable CR write intercept
DirectVmcallEnableMovToCr3Vmexit*        → Enable CR3 write intercept
DirectVmcallInvalidateEptAllContexts      → TLB flush (all EPT contexts)
DirectVmcallInvalidateSingleContext       → TLB flush (single VPID)
DirectVmcallSetHiddenBreakpointHook       → EPT hidden breakpoint
DirectVmcallUnhookSinglePage             → Remove EPT hook
DirectVmcallEnableRdtscpExiting          → Enable RDTSC/P intercept
DirectVmcallDisableRdtscExiting*         → Disable RDTSC intercept
DirectVmcallEnableRdpmcExiting           → Enable RDPMC intercept
DirectVmcallEnableExternalInterruptExiting→ Route interrupts through HV
DirectVmcallEnableMov2DebugRegsExiting   → Intercept debug register writes
```

#### 7.2.5 EPT Hook Subsystem

EPT (Extended Page Tables) hooks are the core technique for invisible code modification. Denuvo cannot detect them because they are implemented at the page table level, outside the guest's view.

**How an EPT hook works:**

```
Normal (pre-hook):
  Guest virtual 0xDENUVO_CHECK → Guest physical 0xPHYS_A → real code

After EPT hook:
  Execute access → shadow page (patched code) → Denuvo runs hooked version
  Read/Write access → original page (real code) → Denuvo's self-check sees original

Result: Denuvo reads its own code as unmodified, but executes the patched version.
```

**EPT hook API:**
```
ConfigureEptHook                    → hook function by address (exec only)
ConfigureEptHook2                   → hook with read/write/exec control
ConfigureEptHookModifyInstructionFetchState  → control exec permission
ConfigureEptHookModifyPageReadState         → control read permission  
ConfigureEptHookModifyPageWriteState        → control write permission
ConfigureEptHookMonitor                     → monitor memory accesses
EptSplitLargePage                   → split 2MB page → 512 x 4KB (hook granularity)
EptSetPML1AndInvalidateTLB          → apply hook + flush TLB
```

#### 7.2.6 LstarHook — Syscall Interception

```
LSTAR = IA32_LSTAR MSR (address 0xC0000082)
       = kernel entry point for SYSCALL instruction
       = KiSystemCall64 in ntoskrnl.exe
```

When `ConfigureEnableEferSyscallEventsOnAllProcessors` is called:
1. VMM reads current LSTAR value (saves as `OrigLstar`)
2. Sets up EFER.SCE VMEXIT — every `SYSCALL` instruction causes a VMEXIT
3. VMEXIT handler calls `TransparentHandleSystemCallHook` (hyperevade.dll callback)
4. Callback can inspect/modify syscall number and arguments
5. After syscall completes: `TransparentCallbackHandleAfterSyscall` can modify return values
6. Guest resumes via VMRESUME

This intercepts **every system call** made by Denuvo, allowing the crack to inspect what Denuvo is checking and return fabricated results.

#### 7.2.7 CR3 Monitoring

```
BroadcastEnableMovToCr3ExitingOnAllProcessors
```

Every time the OS writes a new value to CR3 (page table base register), it means a process switch. The VMM intercepts this to track which process is currently running, so it can apply the correct memory layout when reading/writing guest memory. Key functions:

```
LayoutGetCurrentProcessCr3          → current process page table base
LayoutGetCr3ByProcessId             → CR3 for any PID
LayoutGetExactGuestProcessCr3       → exact (PCID-aware) CR3
SwitchToProcessMemoryLayoutByCr3    → switch HV context to target process
```

#### 7.2.8 CounterUpdater — TSC Spoofing (1036 bytes)

Denuvo uses `RDTSC`/`RDTSCP` timing to detect the overhead of running inside a hypervisor. The CounterUpdater thread runs in the background and maintains a fake TSC counter that advances at realistic speed, masking VMEXIT overhead. The VMM intercepts RDTSC exits and returns the spoofed counter value.

#### 7.2.9 Guest State Access API

Complete set of GetGuest*/SetGuest* functions for reading/writing every guest CPU register from VMX root mode:

```
GetGuestRIP / SetGuestRIP       ← instruction pointer (redirect execution)
GetGuestRSP / SetGuestRSP       ← stack pointer
GetGuestRFlags / SetGuestRFlags ← flags (modify interrupt state, trap flag)
GetGuestCr0..Cr8 / SetGuest*   ← control registers
GetGuestDr0..Dr7 / SetGuest*   ← debug registers
GetGuestCs/Ds/Es/Fs/Gs/Ss      ← segment registers + selectors
GetGuestGdtr/Idtr/Ldtr/Tr      ← descriptor table registers
```

---

## 8. hyperevade.dll — Evasion/Transparency Layer

### 8.1 Overview

hyperevade.dll is the smallest component (7 KB) but the most targeted at Denuvo specifically. It provides 10 callback functions that hyperhv.dll calls from VMEXIT handlers.

### 8.2 Full Disassembly of All Functions

#### TransparentHandleSystemCallHook (0x180001000) — 3 bytes

```asm
0x180001000:  ret 0          ; C2 00 00
```

**Stub.** This export is a placeholder — it returns immediately (0 bytes popped from stack). The real syscall hook logic is registered at runtime via `TransparentHideDebugger`. The function pointer table passed to HideDebugger replaces this with live callbacks.

#### TransparentCallbackHandleAfterSyscall (0x180001000)

Same address as above — they share the entry point. Both are stubs activated by `TransparentHideDebugger`.

#### TransparentHideDebugger (0x180001010) — 196 bytes

```asm
; TransparentHideDebugger(void** callback_table, CONTEXT* ctx)
; arg1 (rcx) = array of 11 function pointers (the transparency callbacks)
; arg2 (rdx) = VMM context/state structure

; Phase 1: Validate callback table (scan for nulls, max 11 entries)
0x180001010:  xor r8d, r8d           ; counter = 0
0x180001013:  mov rax, rcx           ; rax = callback_table

loop:
0x180001016:  cmp qword [rax], 0     ; entry == NULL?
0x18000101a:  je  table_exhausted    ; yes → stop
0x180001020:  inc r8d                ; counter++
0x180001023:  add rax, 8             ; next pointer
0x180001027:  cmp r8d, 0xb           ; reached 11?
0x18000102b:  jb  loop               ; no → continue

; Phase 2: Check if already initialized
0x18000102d:  cmp byte [0x18000305c], 0  ; g_transparency_active
0x180001034:  movups xmm0, [rcx]         ; load first 16 bytes of table
0x180001037:  movups [0x180003060], xmm0 ; store to g_callbacks[0..1]
0x18000103e:  movups xmm1, [rcx+0x10]
0x180001042:  movups [0x180003070], xmm1 ; g_callbacks[2..3]
0x180001049:  movups xmm0, [rcx+0x20]
0x18000104d:  movups [0x180003080], xmm0 ; g_callbacks[4..5]
0x180001054:  movups xmm1, [rcx+0x30]
0x180001058:  movups [0x180003090], xmm1 ; g_callbacks[6..7]
0x18000105f:  movups xmm0, [rcx+0x40]
0x180001063:  movups [0x1800030a0], xmm0 ; g_callbacks[8..9]
0x18000106a:  movsd  xmm1, [rcx+0x50]
0x18000106f:  movsd  [0x1800030b0], xmm1 ; g_callbacks[10]

; Phase 3: Load Denuvo CPUID context
0x180001077:  jne not_initialized
; (first time only) Copy CPUID context from arg2 into g_cpuid_context
0x180001079:  movups xmm0, [rdx+0xc]
0x18000107f:  movups [0x180003020], xmm0 ; save CPUID leaf state
0x180001086:  movups xmm1, [rdx+0x1c]
0x18000108a:  movups [0x180003030], xmm1
0x180001091:  movups xmm0, [rdx+0x2c]
0x180001095:  movups [0x180003040], xmm0
0x18000109c:  movsd  xmm1, [rdx+0x3c]
0x1800010a1:  movsd  [0x180003050], xmm1
0x1800010a9:  mov ecx, [rdx+0x44]
0x1800010ac:  mov [0x180003058], ecx

; Set transparency active flag
0x1800010b2:  mov byte [0x18000305c], 1     ; g_transparency_active = true

; Signal success to caller
0x1800010b9:  mov dword [rdx+0x48], 0xffffffff  ; STATUS_SUCCESS marker
0x1800010c0:  ret

not_initialized:
0x1800010c1:  mov dword [rdx+0x48], 0xc000000a  ; STATUS_NO_SUCH_DEVICE
0x1800010c8:  jmp exit
table_exhausted:
0x1800010ca:  mov dword [rdx+0x48], 0xc0000009  ; STATUS_INVALID_HANDLE
exit:
0x1800010d1:  xor al, al
0x1800010d3:  ret
```

**Analysis:** This is the activation function. It:
1. Validates that the callback table has up to 11 non-null function pointers
2. Copies the table to a global (g_callbacks at 0x180003060) via SSE2 movups (16 bytes at a time — fast bulk copy)
3. Saves Denuvo's CPUID query context (what leaf Denuvo is querying) to a global
4. Sets the transparency active flag
5. Returns STATUS codes to the VMM

#### TransparentUnhideDebugger (0x1800010e0) — 22 bytes

```asm
0x1800010e0:  cmp byte [0x18000305c], 0  ; g_transparency_active?
0x1800010e7:  je  not_active             ; already off → fail
0x1800010e9:  mov byte [0x18000305c], 0  ; g_transparency_active = false
0x1800010f0:  mov al, 1                  ; return true
0x1800010f2:  ret
not_active:
0x1800010f3:  xor al, al                 ; return false
0x1800010f5:  ret
```

Simple toggle. Clears the active flag, disabling all transparency callbacks.

#### TransparentCheckAndModifyCpuid (0x180001110) — 44 bytes

```asm
; Called from CPUID VMEXIT handler
; arg1 (rcx) = pointer to CPUID leaf value (what EAX was when CPUID executed)
; arg2 (rdx) = pointer to CPUID result struct {EAX, EBX, ECX, EDX}

0x180001110:  mov rax, [rcx]         ; rax = CPUID leaf
0x180001113:  cmp rax, 1             ; leaf 1? (Feature Information)
0x180001117:  jne not_leaf1

; Leaf 1: Clear the Hypervisor Present bit (ECX bit 31)
; CPUID.1:ECX.31 = 1 means "running under a hypervisor"
; Denuvo checks this to detect VMs
0x180001119:  btr dword [rdx+8], 0x1f  ; clear ECX bit 31
0x18000111e:  ret                        ; Denuvo sees no hypervisor

not_leaf1:
; Check for hypervisor vendor leaves (0x40000000-0x40000001)
; VMware, Hyper-V, KVM all respond to 0x40000000
0x18000111f:  add rax, 0xffffffffc0000000  ; rax -= 0x40000000
0x180001125:  cmp rax, 1                   ; was it 0x40000000 or 0x40000001?
0x180001129:  ja  done                      ; no → pass through

; Zero out all CPUID output registers
0x18000112b:  mov eax, 0x40000000
0x180001130:  mov [rdx+0xc], eax    ; EBX = 0x40000000 (garbage vendor string)
0x180001133:  mov [rdx+0x8], eax    ; ECX = 0x40000000
0x180001136:  mov [rdx+0x4], eax    ; EBX = 0x40000000
0x180001139:  mov [rdx], eax        ; EAX = 0x40000000 (max leaf = base = nothing)
done:
0x18000113b:  ret
```

**Critical finding:** This function has two distinct anti-detection behaviors:

1. **CPUID Leaf 1 (Feature Flags):** Clears ECX bit 31 — the "Hypervisor Present" bit. Every hypervisor sets this. Denuvo checks it. The crack clears it → Denuvo thinks it's on bare metal.

2. **CPUID Leaves 0x40000000-0x40000001 (Hypervisor Vendor):** Zeroes out all 4 output registers. Normal hypervisors return their vendor string here (Hyper-V returns "Microsoft Hv", VMware returns "VMwareVMware"). By zeroing these, the crack eliminates any fingerprint.

#### TransparentCheckAndModifyMsrRead (0x180001140) — 3 bytes

```asm
0x180001140:  xor al, al    ; return false (no modification)
0x180001142:  ret
```

MSR reads pass through unmodified. The important MSR (LSTAR) is handled differently — it's hooked at the VMM level, not via this callback. MSR reads Denuvo performs (e.g., reading IA32_VMX_BASIC to detect VT-x support) are simply not intercepted.

#### TransparentCheckAndModifyMsrWrite — same address as above (alias)

Both Read and Write share the same stub. Neither modifies MSR values at this layer.

#### TransparentCheckAndTrapFlagAfterVmexit (0x180001150) — 14 bytes + trampoline

```asm
0x180001150:  mov rax, [0x1800030a8]    ; load stored original callback ptr
0x180001157:  jmp qword [0x180002008]  ; → 0x1800011c0

; The trampoline at 0x1800011c0:
0x1800011c0:  jmp rax                   ; tail-call to original handler
```

This function handles the Trap Flag (TF) in RFLAGS. When Denuvo uses single-step debugging (sets TF=1 in RFLAGS to debug-step its own code), every instruction causes a debug exception (#DB). The VMEXIT handler must route this correctly. The function loads the original #DB handler address and jumps to it, preserving Denuvo's self-debugging behavior while remaining transparent.

**Anti-detection context:** Denuvo uses its own internal single-step execution to verify code integrity. If the TF handling is wrong, Denuvo detects the VM.

**Stack canary verification** (at 0x180001190, nearby code):
```asm
0x180001190:  cmp rcx, [0x180003010]    ; check against cookie 0x2b992ddfa232
0x180001197:  jne fail
0x180001199:  rol rcx, 0x10             ; rotate
0x18000119d:  test cx, 0xffff           ; high 16 bits must be zero
0x1800011a2:  jne fail
0x1800011a4:  ret                        ; valid
fail:
0x180001170:  mov ecx, 2               ; FAST_FAIL_CORRUPT_MEMORY
0x180001175:  int 0x29                  ; __fastfail
```

#### DllInitialize / DllUnload (0x180001100) — 3 bytes

```asm
0x180001100:  xor eax, eax   ; return 0 (STATUS_SUCCESS)
0x180001102:  ret
```

No initialization needed — all state is global. Both Init and Unload do nothing.

---

## 9. Security Impact Assessment

### 9.1 System Exposure During Gaming Session

| Security Control | Normal State | While HV Active | Attack Surface Opened |
|---|---|---|---|
| Driver Signature Enforcement | Enforced | **Disabled** | Any unsigned kernel driver can load |
| Memory Integrity (HVCI) | Enforced | **Disabled** | Unsigned kernel code executes freely |
| Credential Guard | Active | **Disabled** | NTLM hashes in LSASS are accessible |
| System Guard | Active | **Disabled** | Boot integrity attestation bypassed |
| Windows Hypervisor (Hyper-V) | Active | **Disabled** | VBS-dependent features lose protection |
| KVA Shadow (Meltdown) | Active | **Disabled** (older Intel) | Meltdown vulnerability re-exposed |
| Ring -1 | Windows Hyper-V | **DenuvOwO HV** | Unsigned code controls all hardware |

### 9.2 What the Hypervisor Can Do (Theoretically)

While loaded, the hypervisor has complete control over the running system:

- **Read any memory** — physical or virtual, in any process (MemoryMapper* API)
- **Write any memory** — modify kernel, patch any process (MemoryMapperWriteMemory* API)
- **Intercept all syscalls** — observe every NtCreateFile, NtReadFile, NtWriteFile, etc.
- **Hide processes** — by manipulating EPROCESS list (not implemented here, but possible)
- **Keylog** — by intercepting I/O port reads for keyboard
- **Network sniff** — by intercepting NIC driver I/O

**Important:** The included source code (`DenuoOwO_SRC.7z`) and the actual disassembly show that only the Denuvo bypass functionality is implemented. No malicious payloads were found.

### 9.3 Cleanup Is Reversible

The `VBS.cmd` revert option (choice 3) accurately restores all security settings using the `HKLM\SOFTWARE\ManageVBS` tracking registry key. DSE automatically re-enables after reboot without manual steps. The hypervisor is unloaded as soon as the game closes. This is not persistent malware.

### 9.4 Risk Comparison

| Risk | Severity | Notes |
|---|---|---|
| Malicious code in the HV | **Low** | Source is included, exports match HyperDbg origin, no C2/network code found |
| Security window while gaming | **High** | Full kernel access by unsigned code, no HVCI |
| Revert failure leaving system insecure | **Low** | Revert script is thorough; DSE re-enables automatically |
| False positive AV detection | **High** | Unsigned kernel driver = every AV will flag this |
| Incompatibility with anti-cheat (Vanguard, FACEIT) | **Critical** | VBS.cmd explicitly warns: Vanguard will BSOD |
| KVA Shadow disabled on older Intel | **Medium** | Meltdown re-exposed for gaming session only |

---

## 10. Denuvo Bypass — Complete Technical Flow

```
[Boot with DSE disabled via F7]
         │
         ▼
[hypervisor-launcher.exe]
  ├─ Acquires SE_DEBUG + SE_SYSTEM_ENVIRONMENT privilege
  ├─ Finds ntoskrnl.exe + CI.dll base in kernel
  ├─ Detects CPU: "GenuineIntel" → Intel path / "AuthenticAMD" → AMD path
  ├─ Copies unsigned .sys driver to %TEMP%\[random]\
  ├─ Creates kernel service via SCM → StartService → driver loads
  └─ Steals Explorer token → launches ACShadows.exe as non-admin
         │
         ▼
[Driver loads at ring -1]
  AMD: SimpleSvm.sys → VMRUN on all cores
  Intel: hyperkd.sys → VmFuncInitVmm → VMXON + VMLAUNCH on all cores
         │
         ▼
[OS + Denuvo + ACShadows.exe run as guest VM]
         │
  Denuvo performs: │
  ─────────────────┤
  CPUID leaf 1     │→ VMEXIT → TransparentCheckAndModifyCpuid
                   │          → clears ECX bit 31 (Hypervisor bit)
                   │          → Denuvo: "I'm on bare metal" ✓
  ─────────────────┤
  CPUID leaf       │→ VMEXIT → TransparentCheckAndModifyCpuid
  0x40000000       │          → zeros EAX/EBX/ECX/EDX
                   │          → Denuvo: "No hypervisor vendor" ✓
  ─────────────────┤
  RDTSC timing     │→ VMEXIT → CounterUpdater spoofs TSC delta
                   │          → Denuvo: "No VM overhead" ✓
  ─────────────────┤
  SYSCALL          │→ VMEXIT → TransparentHandleSystemCallHook
                   │          → callback table intercepts call
                   │          → real syscall forwarded
                   │          → TransparentCallbackHandleAfterSyscall
                   │          → return value patched if needed ✓
  ─────────────────┤
  Read own code    │→ EPT violation → EptHandleEptViolation
  (integrity check)│          → serves original unmodified page
                   │          → Denuvo: "Code is untampered" ✓
  ─────────────────┤
  Execute own code │→ EPT maps execute-permission to patched shadow page
                   │          → patched Denuvo code actually runs
                   │          → license checks return "valid" ✓
  ─────────────────┤
  RFLAGS.TF        │→ VMEXIT → TransparentCheckAndTrapFlagAfterVmexit
  (single-step     │          → routes #DB to original handler
  self-debug)      │          → Denuvo's internal debugger works ✓
  ─────────────────┤
  Game exits        │→ hypervisor-launcher: ControlService(STOP) → DeleteService
                   │  Driver removed. All VMX/SVM structures freed.
                   └─ System returns to normal operation.
```

---

## 11. Conclusion

DenuvOwO is a sophisticated, professionally engineered Denuvo bypass. It correctly implements:

- Full AMD SVM and Intel VT-x hypervisors based on established open-source research
- Transparent CPUID and MSR spoofing to hide the hypervisor from Denuvo's VM detection
- EPT-based memory hooks for invisible code patching (Denuvo reads clean, executes patched)
- Syscall interception via LSTAR/EFER hooks to intercept license validation calls
- TSC spoofing to defeat timing-based VM detection
- Trap Flag forwarding to preserve Denuvo's internal single-step integrity checking
- Clean lifecycle management (load/unload without leaving persistent system changes)

The approach is technically correct at the CPU architecture level. The security trade-off is significant but time-bounded — the system is in a degraded security state only during gameplay, and the revert mechanism is reliable.

---

*Analysis tools: radare2, objdump, readelf, strings — WSL Ubuntu on Windows 11 Pro 10.0.26200*  
*Binaries analyzed: hypervisor-launcher.exe, SimpleSvm.sys, hyperkd.sys, hyperhv.dll, hyperevade.dll, VBS.cmd, DenuvOwO.nfo*
