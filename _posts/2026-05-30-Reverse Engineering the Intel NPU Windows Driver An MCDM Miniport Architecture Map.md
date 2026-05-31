---
title: Reverse Engineering the Intel NPU Windows Driver - An MCDM Miniport Architecture Map
date: 2026-05-21 15:01:00 +0100
categories:
  - Vulnerability Research
  - Reverse Engineering
  - Drivers
tags:
  - binary-analysis
  - defense
  - windows
  - intel
  - NPU-chips
toc: true
target: Intel® NPU Driver for Windows - npu_kmd.sys
---
![[/assets/img/posts/2026-05-30-reverse-engineering-the-intel-npu-windows-driver-an-mcdm-miniport-architecture-map/20260531153109.png]]
## Foreword

After working a bit on Nvidia driver installers/drivers, and tooling for binary analysis, I decided to look for another cool project. Since I am constantly on foot, going between courses or cities, my laptop stays almost all the time with me. It was just recently when I found about the NPU chip that comes with my Intel Ultra CPU on the laptop. Never before I needed this so-called "AI boost" in an application of mine. However, I still think it is quite cool piece of tech.

The first thing I decided to take on is running some local models on it and even made a small harness to deal with on-device translation using these NPU-loaded models. Intel NPUs, however, are optimized for running only OpenVINO models. 
![[/assets/img/posts/2026-05-30-reverse-engineering-the-intel-npu-windows-driver-an-mcdm-miniport-architecture-map/20260520142105.png]] You can learn what is OpenVINO here --> [link](https://www.intel.cn/content/dam/develop/public/us/en/documents/openvino-toolkit-llms-solution-white-paper.pdf). The key features span from easy integration such as multi-framework support (PyTorch, TensorFlow, TensorFlow Lite, PaddlePaddle, ONNX), optimized deployment and improved performance of LLMs on consumer Intel hardware.

As a sec guy, I also started fooling around. I went from poking at loaded weights and went all the way to trying to reverse the drivers for this. And so, this is my in-progress reverse engineering against a relatively obscure Windows kernel driver (while there are some relatively similar jobs done in the past, nothing explains the operations of the security-relevant mechanics. If there are and you can link them, please do send them to me, so I can include them here). Cool posts on this topic:

- [Reversing and Exploiting Samsung's Neural Processing Unit](https://blog.longterm.io/samsung_npu.html)
- [Fall of the machines: Exploiting the Qualcomm NPU (neural processing unit) kernel driver](https://github.blog/security/vulnerability-research/fall-of-the-machines-exploiting-the-qualcomm-npu-neural-processing-unit-kernel-driver/)

So, what is this post? - It's an architecture map and documentation, not a vulnerability disclosure. It contains no confirmed bug and I don't claim one (still ;p). Its purpose is to record how `npu_kmd.sys` is built, how it attaches to the Windows graphics stack, and how an MCDM miniport of this kind is reverse engineered, so the work is reusable as a starting point for anyone auditing this driver or a comparable one. Work paused here for other bug bounties and ideas, but more on this is in the end. This is the first post out of several others that will be coming out, with each one being more offensive than the previous. Right now, let's start slow and understand the whole scene.

The target driver is `npu_kmd.sys`, identified as `Intel(R) NPU Driver` from `Intel(R)`. It is a kernel-mode binary that sits behind both the Microsoft DirectX graphics stack (through the D3D12 user-mode driver path) and the OpenVINO Level Zero stack, mediating access to Intel's Neural Processing Unit (the "AI Boost" device in Device Manager, Windows). 
![[/assets/img/posts/2026-05-30-reverse-engineering-the-intel-npu-windows-driver-an-mcdm-miniport-architecture-map/20260531124127.png]] 
_Figure 1 shows where npu_kmd.sys attaches in the Windows graphics dispatch hierarchy. The display path (grey) connects to dxgkrnl via WDM device objects with IRP-based dispatch. The NPU compute path (blue) connects via MCDM DDI callback registration. It creates no device object and exposes no IOCTL endpoint. Section 3 develops this distinction in full._

---

## 1. Why the Intel NPU is an interesting target

There are three things make the Intel NPU driver an attractive research target.

It is new. Intel has been shipping a discrete NPU as part of the consumer CPU package only since Meteor Lake's launch in late 2023. The Windows driver has gone through dozens of revisions with each release adding features and DDI surface. New code is obviously more bug-prone than mature code, and Intel itself has disclosed three "improper conditions check" CVEs in this driver family within a single advisory ([INTEL-SA-01403](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-01403.html)), all patched in version `32.0.100.4297`.

It has a Linux counterpart ([here](https://github.com/intel/linux-npu-driver)). The mainline Linux kernel has shipped the `ivpu` driver (in `drivers/accel/ivpu/`) since kernel 6.3. The Linux driver is open source, well-commented, and shares the firmware IPC protocol (the JSM, or Job Submission Messages, API defined in `vpu_jsm_api.h`) with the Windows driver. This makes Linux useful as it can be used for newcomers to understand foundations and also to, sometimes, be used when decompiling produces an unhelpful output of a Windows function that constructs a JSM message, the Linux source for the same operation is a translatable reference or at least it may be able to help even a bit.

It is reachable from low-privilege contexts. The NPU is accessible via DirectML, which any unprivileged Windows process can use, and via Level Zero, which is similarly accessible. Any vulnerability in this driver is therefore reachable without elevated privileges on the host. That makes the privilege escalation impact direct: an LPE in `npu_kmd.sys` is, by definition, exploitable from a normal user account.

---

## 2. Unpacking the installer

The Intel NPU Windows driver ships as a single self-extracting executable: `npu_win_32_0_100_4723.exe`. The outer wrapper is a standard PE32+ x86-64 executable produced with an SFX (self-extracting archive) version 3.12.0.0 toolchain. Its only purpose is to extract a RAR5 solid archive and invoke the actual installer.

The archive is solid, individual files cannot be extracted separately so the entire stream must be decompressed in sequence. The archive is extracted with 7-Zip rather than by executing the SFX.

The unpacked tree contains:

```
unpacked_npu/
├── installation_readme.txt
├── Installer.exe                    # GUI driver installer, 74.7 MB - runs as Administrator
└── NPU/
    ├── npu.cat                      # Authenticode catalog (WHQL signature chain)
    ├── npu.inf                      # Plaintext driver manifest
    ├── npu_kmd.sys                  # Kernel-mode driver - PRIMARY TARGET
    ├── npu_blob_parser.dll          # Neural network blob parser
    ├── npu_d3d12_umd.dll            # DirectX 12 / DirectML user-mode driver
    ├── npu_driver_compiler.dll      # On-device model compiler (77 MB)
    ├── npu_level_zero_umd.dll       # Level Zero user-mode driver
    ├── tbb12.dll                    # Intel TBB 2021 runtime
    ├── tbbmalloc.dll                # TBB scalable allocator
    ├── ze_loader.dll                # Level Zero loader / dispatcher
    ├── ze_tracing_layer.dll
    ├── ze_validation_layer.dll
    ├── third-party-programs.txt
    └── firmware/
        ├── npu27_firmware.bin       # VPU 2.7 - Meteor Lake
        ├── npu4_firmware.bin        # VPU 4.0 - Arrow Lake
        ├── npu5_firmware.bin        # VPU 5.0 - Lunar Lake
        ├── npu5_hws_firmware.bin    # VPU 5.0 HW scheduler firmware
        └── npu5_oss_firmware.bin    # VPU 5.0 OSS component
```

The `.inf` file is plaintext and is the first artifact to read on any Windows driver target. It is the manifest that tells the operating system what hardware to bind the driver to, what service name to register, what filesystem destinations the files copy to, and what registry keys to create. For this target, the relevant entries reveal hardware IDs:

- `PCI\VEN_8086&DEV_7D1D` (Meteor Lake)
- `PCI\VEN_8086&DEV_AD1D` (Arrow Lake)
- `PCI\VEN_8086&DEV_643E` (Lunar Lake)
- Service name. The service-name detail matters more than it should - see Section 7.1.

The installer's structure matters too. `Installer.exe` is large (74.7 MB), runs at Administrator privilege during driver installation, and on Intel's tradition of installer-side bugs, is itself a candidate for privilege escalation through DLL hijacking or unsafe directory creation. (As of now, I haven't inspected more deeply the installer mechanics)

---

## 3. Architecture of `npu_kmd.sys`

Some readers might have the following assumption - `npu_kmd.sys` to be a conventional WDM or KMDF driver - a driver that creates a device object, registers IOCTL handlers via `DriverObject-->MajorFunction[IRP_MJ_DEVICE_CONTROL]` (WDM) or via a KMDF `EvtIoDeviceControl` callback, and accepts requests from user mode via `DeviceIoControl`. Most Linux DRM-style drivers translate to Windows as KMDF, and the Linux `ivpu` reference uses the DRM IOCTL pathway. The natural expectation is that the Windows port preserves the IOCTL surface.

However, this assumption is wrong, and recognizing that it is wrong was important and it is something new that I learnt.

`npu_kmd.sys` is an MCDM driver. MCDM stands for [Microsoft Compute Driver Model](https://learn.microsoft.com/en-us/windows-hardware/drivers/display/mcdm), and it is the kernel-side framework Microsoft introduced for compute-only accelerators that participate in the graphics dispatch infrastructure without exposing display capabilities. MCDM drivers register themselves with `dxgkrnl.sys` (the DirectX graphics kernel) as miniports. They do not maintain their own IOCTL dispatch table. They do not create their own device object with an IOCTL endpoint. Part of their attack surface is the DDI callback table they hand to `dxgkrnl` during registration, which `dxgkrnl` then invokes on their behalf when user-mode D3DKMT calls (the kernel-mode-thunk D3D kernel interface) arrive from above.

![[/assets/img/posts/2026-05-30-reverse-engineering-the-intel-npu-windows-driver-an-mcdm-miniport-architecture-map/20260520170243.png]] _Figure 2 - MCDM architecture overview._

A WDM driver imports `IoCreateDevice`, `IoCreateSymbolicLink`, and `IofCompleteRequest`. A KMDF driver imports `WdfDriverCreate`, `WdfDeviceCreate`, and `WdfIoQueueCreate`. `npu_kmd.sys` imports neither set.

Enumeration of the PE import table (Ghidra Symbol Tree → Imports) resolves imports from exactly four modules:

```
NTOSKRNL.EXE   ExAllocatePool2, ExAllocatePoolWithTag, ExFreePoolWithTag,
               IoAllocateMdl, IoBuildDeviceIoControlRequest,
               IoGetCurrentProcess,
               IoRegisterDeviceInterface, IoRegisterPlugPlayNotification,
               IoWMIRegistrationControl, KeAcquireInStackQueuedSpinLock,
               MmProbeAndLockPages, MmMapLockedPagesSpecifyCache,
               ObReferenceObjectByHandle, ProbeForRead, ProbeForWrite,
               PsCreateSystemThread, RtlGetVersion, ZwLoadDriver, ... (and others)
               
HAL.DLL        KeQueryPerformanceCounter, KeStallExecutionProcessor

KSECDD.SYS     BCryptOpenAlgorithmProvider, BCryptHashData, BCryptFinishHash, ...

WPPRECORDER.SYS imp_WppRecorderConfigure
```

Full list: <a href="/assets/txt/2026-05-30-reverse-engineering-the-intel-npu-windows-driver-an-mcdm-miniport-architecture-map/npu_kmd_import_table.txt">Full import table of npu_kmd.sys</a>

Two observations follow directly from this list. First, the absence of `IoCreateDevice`/`IoCreateSymbolicLink` confirms the driver creates no device object of its own, and the absence of any `Wdf*` import confirms it is not KMDF-bound. Second, there is no static import of `dxgkrnl.sys` either. The driver does not link against the graphics kernel at load time. The MCDM interface is instead acquired _dynamically at runtime_: `DriverEntry` populates a callback structure and hands it to an internal routine (`IntelNPU_FrameworkInit`) that acquires the `dxgkrnl` interface through `IntelNPU_DxgkAcquireInterface__` and negotiates an interface IOCTL code via `DlpGetIoctlCode`. The classification of this driver as an MCDM miniport therefore rests on the _absence_ of both the WDM and KMDF marker sets combined with the presence of this runtime interface-negotiation path, not on a static `dxgkrnl` import. The functions the driver registers with `dxgkrnl` are detailed below.

The function the loader calls at `DriverEntry` does not establish an IOCTL endpoint. It zero-initializes a callback structure (a stack local, cleared with `memset(&Callbacks, 0, 0x608)`), populates it with function pointers, and passes it to `IntelNPU_FrameworkInit`, which forwards it to `dxgkrnl` after acquiring the graphics-kernel interface. The structure is identified internally as a `DriverCallbacks` block; its first dword is a version field (`Callbacks._0_4_ = 0x11008` in the analyzed build).

The slot population is extensive, and the full set is mapped. Across `DriverEntry`, the structure receives **79 distinct writes**: one 4-byte version field at offset `0`, 50 unconditional 8-byte callback pointers, and 28 further 8-byte pointers gated behind Windows build-number checks. The complete enumeration was produced by walking every write into the `[base, base+0x608)` stack region in the `DriverEntry` decompilation and reading the build-number predicate that dominates each gated write; the slot offsets below are decimal, matching Ghidra's `Callbacks._NNN_S_` field notation. The unconditional core is listed first:

```c
// --- version field ---
Callbacks._0_4_      = 0x11008;                  // structure / interface version

// --- unconditional callback pointers (50), by struct offset ---
Callbacks._8_8_      = thunk_FUN_140005420;      // OnInitialize (decompiler-named)
Callbacks._16_8_     = FUN_1403aac70;            // OnStart (swapped to IntelNPU_OnStart_DxgkInterposer inside FrameworkInit)
Callbacks._24_8_     = FUN_1403aadd0;
Callbacks._32_8_     = FUN_1403aae40;
Callbacks._40_8_     = FUN_140010940;
Callbacks._48_8_     = FUN_140002640;
Callbacks._56_8_     = FUN_1400026d0;
Callbacks._64_8_     = FUN_140010900;
Callbacks._72_8_     = FUN_140010910;
Callbacks._80_8_     = FUN_140010920;
Callbacks._88_8_     = FUN_1400027c0;
Callbacks._104_8_    = FUN_1400108f0;
Callbacks._112_8_    = FUN_1403aacf0;            // OnStop (decompiler-named)
Callbacks._136_8_    = FUN_140002c60;
Callbacks._144_8_    = FUN_140003130;
Callbacks._152_8_    = FUN_140032560;
Callbacks._160_8_    = FUN_1400327d0;
Callbacks._168_8_    = FUN_140032910;
Callbacks._176_8_    = FUN_140032c60;
Callbacks._216_8_    = FUN_140003430;
Callbacks._224_8_    = FUN_140003390;
Callbacks._256_8_    = FUN_140002870;
Callbacks._264_8_    = FUN_1400028f0;
Callbacks._272_8_    = FUN_140002740;
Callbacks._280_8_    = FUN_140002960;
Callbacks._400_8_    = FUN_1400031e0;
Callbacks._408_8_    = FUN_1400329f0;
Callbacks._416_8_    = FUN_140032ba0;
Callbacks._464_8_    = KmCreateContext_Wrapper;  // FUN_140002ed0 -> KmCreateContext (FUN_14001ee70), Section 4
Callbacks._472_8_    = FUN_140002fc0;            // adjacent slot - destroy-context candidate
Callbacks._568_8_    = FUN_140002b40;
Callbacks._576_8_    = FUN_140003630;
Callbacks._584_8_    = FUN_1400036c0;
Callbacks._592_8_    = FUN_140003760;
Callbacks._640_8_    = FUN_140002be0;
Callbacks._664_8_    = FUN_140003250;
Callbacks._696_8_    = FUN_140002cf0;
Callbacks._704_8_    = FUN_140002e10;
Callbacks._720_8_    = FUN_140003950;
Callbacks._728_8_    = FUN_1400032e0;
Callbacks._736_8_    = FUN_14003d3c0;
Callbacks._768_8_    = FUN_1400034e0;
Callbacks._776_8_    = FUN_140003590;
Callbacks._816_8_    = FUN_140010930;
Callbacks._856_8_    = FUN_140032c30;
Callbacks._1104_8_   = FUN_140010950;
Callbacks._1112_8_   = FUN_1400049f0;
Callbacks._1120_8_   = FUN_140004a30;
Callbacks._1520_8_   = FUN_140002a50;
Callbacks._1528_8_   = FUN_140003060;            // highest populated offset
```

The complete map, covering all 79 slots with decimal and hex offset, write size, resolved target, and build-number gate, is also provided as a standalone, sortable HTML companion:

<a href="/assets/txt/2026-05-30-reverse-engineering-the-intel-npu-windows-driver-an-mcdm-miniport-architecture-map/npu_kmd_callback_map.txt">Full DriverEntry callback-slot map</a>

Several structural facts follow from the complete map. The context-creation slot is offset `_464`, holding `KmCreateContext_Wrapper` (`FUN_140002ed0`), which in turn invokes `KmCreateContext` (`FUN_14001ee70`) (the function is analyzed in Section 4), and its immediate neighbor `_472` (`FUN_140002fc0`) is the natural destroy-context candidate. The decompiler recovers three slots under symbolic names rather than raw offsets: `OnInitialize` at `_8`, `OnStart` at `_16`, and `OnStop` at `_112`. The lifecycle handlers cluster in the driver's own `0x1403aaXXX` range (`OnStart` = `FUN_1403aac70`, `OnStop` = `FUN_1403aacf0`, with `_24`/`_32` = `FUN_1403aadd0`/`FUN_1403aae40` adjacent); the bulk of the remaining unconditional slots point into the `FUN_140002xxx`–`FUN_140004xxx` and `FUN_14003xxxx` ranges, and a small post-version cluster (`_40`, `_64`, `_72`, `_80`, `_104`, `_816`, `_1104`) targets the contiguous `FUN_1400108f0`–`FUN_140010950` group.

The second structural fact is that a large part of the callback surface is **conditional on the Windows build number**, gated by three `RtlGetVersion`-driven thresholds. This is not a handful of slots, but it accounts for 28 of the 79 writes, and the great majority activate only on the 24H2 development line:

```c
// build > 21999  (Windows 11 21H2 / build 22000+)  --  1 slot
if (21999 < local_148.dwBuildNumber) {
    Callbacks._208_8_  = FUN_1400038a0;
}

// build > 24999  (25000+, the 24H2 line; 24H2 RTM is build 26100)  --  26 slots
if (24999 < local_148.dwBuildNumber) {
    Callbacks._880_8_  = FUN_140003a30;
    Callbacks._888_8_  = FUN_140003a40;
    Callbacks._896_8_  = FUN_140003a50;
    Callbacks._904_8_  = FUN_140003b20;
    Callbacks._912_8_  = FUN_140003dc0;
    Callbacks._920_8_  = 0;                  // explicitly zeroed under this gate
    Callbacks._928_8_  = FUN_140003ba0;
    Callbacks._1032_8_ = 0;                  // explicitly zeroed under this gate
    Callbacks._1056_8_ = FUN_140003f40;
    Callbacks._1064_8_ = FUN_140003eb0;
    Callbacks._1072_8_ = FUN_140004280;
    Callbacks._1080_8_ = FUN_140004030;
    Callbacks._1088_8_ = FUN_140004130;
    Callbacks._1096_8_ = FUN_1400041e0;
    Callbacks._1144_8_ = FUN_140003c50;
    Callbacks._1152_8_ = FUN_140004270;
    Callbacks._1160_8_ = 0;                  // explicitly zeroed under this gate
    Callbacks._1168_8_ = FUN_140003ce0;
    Callbacks._1296_8_ = FUN_140004330;
    Callbacks._1304_8_ = FUN_140004790;
    Callbacks._1312_8_ = FUN_140004500;
    Callbacks._1320_8_ = FUN_1400045f0;
    Callbacks._1488_8_ = FUN_1400043f0;
    Callbacks._1496_8_ = FUN_1400046e0;
    Callbacks._1504_8_ = FUN_140004820;
    Callbacks._1512_8_ = FUN_140004910;
}

// build > 26999  (27000+, post-24H2 / canary)  --  1 slot
if (26999 < local_148.dwBuildNumber) {
    Callbacks._120_8_  = FUN_140004290;
}
```

Also, two observations follow. First, the miniport's callback surface is genuinely OS-version-dependent: 26 of its slots, the `FUN_140003a30`–`FUN_140004910` cluster, consistent with the Windows 11 24H2 hardware-scheduling (HWS) path, are simply absent on systems older than build 25000, and a 27th (`_120`) appears only on 27000+. Second, three of the 24H2-gated writes (`_920`, `_1032`, `_1160`) are explicit _zeroings_ rather than function-pointer installs: on 24H2 the driver actively clears those slots, which a pre-24H2 system never touches after the initial `memset`. The populated structure is then handed, after a preparatory `IntelNPU_PreFrameworkInit()` call, to `IntelNPU_FrameworkInit(DriverObject, RegistryPath, &Callbacks)`, the routine that forwards it to `dxgkrnl`, and the whole population runs only inside the success branch of a `DriverObject`/`RegistryPath` non-NULL check.

A note on the cleared region versus the slot offsets, since the two can look inconsistent at first look. The structure is cleared with `memset(&Callbacks, 0, 0x608)`, and `0x608` is `1544` in decimal. The slot offsets in the `Callbacks._NNN_8_` notation are themselves decimal (Ghidra's convention) so `_640`, `_896`, and the highest assignment `_1528` are decimal offsets `640`, `896`, and `1528`, not hex. `_1528` writes eight bytes ending at offset `1536`, still below `1544`. Every callback slot is therefore written inside the zero-initialized block; there is no write into uninitialized stack space, and the `memset` size is not a defect.

This fact makes any IOCTL-fuzzing plan against this driver, pointless. Searching the binary for `WdfIoQueueCreate` finds nothing. Searching for `IRP_MJ_DEVICE_CONTROL` finds nothing. One actual attack surface is the set of DDI callback functions enumerated above, reached from user mode through the D3DKMT API exported by `gdi32.dll` (functions like `D3DKMTCreateContext`, `D3DKMTSubmitCommand`, `D3DKMTEscape`), which dispatches through `win32k.sys` into `dxgkrnl.sys`, which then invokes the registered DDI on the miniport.

![[/assets/img/posts/2026-05-30-reverse-engineering-the-intel-npu-windows-driver-an-mcdm-miniport-architecture-map/20260521165713.png]] _Figure 3 - Driver initialization and callback-structure registration._

![[/assets/img/posts/2026-05-30-reverse-engineering-the-intel-npu-windows-driver-an-mcdm-miniport-architecture-map/20260525182901.png]] 
_Figure 4 - D3DKMT user-mode-to-DDI dispatch path_

This is structurally different from a conventional driver in three ways that matter for vulnerability research.

The trust boundary sits between `dxgkrnl` and the miniport, not between user mode and the miniport. Anything the miniport receives has already been processed by `dxgkrnl`, which has its own validation layer. Whether `dxgkrnl` probes and copies user pointers before handing them to the miniport, or passes them through raw, is a question that has to be answered separately for each DDI. The DDI prototype (the function signature) is documented by Microsoft, but the _semantics of what_ `dxgkrnl` _does before invoking the DDI_ are not always documented in detail.

![[/assets/img/posts/2026-05-30-reverse-engineering-the-intel-npu-windows-driver-an-mcdm-miniport-architecture-map/20260525183103.png]] _Figure 5. Trust boundary (dxgkrnl validates <---> miniport assumes)_

The miniport's namespace is owned by `dxgkrnl`. The miniport does not own its own device object. `\\.\IntelNPU0` does not exist. The user-mode entry point is `D3DKMTOpenAdapterFromLuid`, which goes through `dxgkrnl`, which routes through to the appropriate miniport based on the LUID. This means any user-mode harness has to use the D3DKMT API, not `CreateFile` on a named device.

Driver Verifier behaves differently against an MCDM miniport than against a WDM driver. Special Pool, IRQL checking, and pool tracking are allocation- and code-path-scoped checks and apply to the miniport's allocations in the standard way; Microsoft's Driver Verifier documentation (the "Driver Verifier options and rule classes" reference on learn.microsoft.com) describes these option scopes. The I/O verification class, by contrast, instruments the IRP dispatch path, and an MCDM miniport exposes no such path, so those checks have no targets on this driver. This split follows from which option _classes_ are code-path-scoped versus IRP-dispatch-scoped, so it can be stated from the driver's static structure alone; a live `verifier /query` on the test machine would only echo the same conclusion.

---

## 4. Static analysis of the `KmCreateContext` DDI

With the MCDM architecture established, the natural starting point is the simplest DDI in the callback table that takes user-controlled data: `DxgkDdiCreateContext`. In the Intel binary the miniport's implementation is internally named `KmCreateContext` (`FUN_14001ee70`); the callback slot `_464` holds its wrapper `KmCreateContext_Wrapper` (`FUN_140002ed0`). The function identity is supported by an embedded build path in the debug strings: `D:\qb\workspace\33077\source\npu-driver\Source\Kmd\render\KmContext.c` and a source line argument (`0x7b`) passed to the logging helper.

`KmCreateContext` receives two arguments. Its prologue, as disassembled by Ghidra, establishes the calling convention and the early validation gate:

```
14001ee70  PUSH RBX
14001ee72  PUSH RDI
14001ee73  PUSH R13
14001ee75  PUSH R14
14001ee77  PUSH R15
14001ee79  SUB RSP,0x70
14001ee7d  MOV R15,qword ptr [RCX + 0x8]   ; R15 = device context from arg1+8
14001ee81  MOV R14,RDX                     ; R14 = the DDI argument structure
14001ee84  MOV RBX,RCX                     ; RBX = arg1 (adapter/process context)
14001ee87  TEST R15,R15
14001ee8a  JZ 0x14001f4da                  ; bail if device context is NULL
14001ee90  MOV EDX,dword ptr [R15 + 0xa8]
14001ee99  MOV ECX,EDX
14001ee9b  AND ECX,0x10
14001ee9e  TEST R14,R14
14001eea1  JZ 0x14001f4da                  ; bail if the DDI argument is NULL
14001eea7  TEST ECX,ECX
14001eea9  MOV EAX,EDI
14001eeab  SETNZ AL
14001eeae  INC EAX                         ; EAX = ((flags & 0x10) != 0) + 1
14001eeb0  CMP dword ptr [R14 + 0x8],EAX    ; compare arg+0x8 against that limit
14001eeb4  JNC 0x14001f4da
14001eeba  CMP qword ptr [R14 + 0x18],RDI   ; arg+0x18 (a pointer field) vs 0
14001eebe  JZ 0x14001eecb
14001eec0  CMP dword ptr [R14 + 0x20],0x1e  ; arg+0x20 compared against 0x1e
14001eec5  JNZ 0x14001f4da
```

The second argument (`RDX`, aliased to `R14` in the prologue) is the DDI argument structure. The disassembly is the definitive reference for the offsets accessed on it: a 4-byte field at `+0x8`, a pointer-width field at `+0x18`, and a 4-byte field at `+0x20`.

Microsoft documents the `DXGKARG_CREATECONTEXT` structure in the DDK header `d3dkmddi.h` ([_DXGKARG_CREATECONTEXT reference, learn.microsoft.com](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/d3dkmddi/ns-d3dkmddi-_dxgkarg_createcontext)). The documented declaration is:

```c
typedef struct _DXGKARG_CREATECONTEXT {
  HANDLE                  hContext;            // [out]
  UINT                    NodeOrdinal;         // [in]
  UINT                    EngineAffinity;      // [in]
  DXGK_CREATECONTEXTFLAGS Flags;               // [in]
  VOID                   *pPrivateDriverData;  // [in]
  UINT                    PrivateDriverDataSize;// [in]
  DXGK_CONTEXTINFO        ContextInfo;          // [out]
} DXGKARG_CREATECONTEXT;
```

On the x64 ABI this places `hContext` at offset `0x00`, `NodeOrdinal` at `0x08`, `EngineAffinity` at `0x0C`, `Flags` at `0x10`, `pPrivateDriverData` at `0x18`, `PrivateDriverDataSize` at `0x20`, and the `ContextInfo` output region from `0x24` (no padding follows the 4-byte `PrivateDriverDataSize`, since `ContextInfo`'s leading member is itself a 4-byte-aligned `UINT`). Per Microsoft's description, `pPrivateDriverData` is a pointer to a block of private data passed from the user-mode display driver to the miniport; `dxgkrnl` does not interpret its contents. The miniport is the only consumer that parses it.

Note that `hContext` is the _first_ field of the structure, at offset `0x00`, and is an `[out]` handle the miniport fills in. This layout fact is important for interpreting the `+0x20` comparison discussed in Section 4.1 and for the structural questions raised in Section 4.2.

### 4.1 What the static analysis showed

`KmCreateContext` allocates a `0x2c18`-byte (11,288-byte) per-process VPU context object. The allocation is not a direct `ExAllocatePool2` call; it goes through an internal pool-allocation wrapper, `FUN_140041d30`, observed in the decompile as:

```c
puVar10 = (undefined8 *)
          FUN_140041d30(lVar3, 0, 0x2c18, 0, uVar13,
                        "D:\\qb\\workspace\\33077\\source\\npu-driver\\Source\\Kmd\\render\\KmContext.c",
                        "KmCreateContext", 0x7b, 0);
```

The corresponding disassembly confirms the size and the pool-tag immediates:

```
14001efc3  MOV R8D,0x2c18                       ; allocation size
14001efc9  MOV dword ptr [RSP + 0x20],0x20504d40 ; pool tag
```

A second, smaller allocation of `0x60` bytes is made later in the same function for a hardware-queue object, using the same wrapper and the same tag (`14001f26b: MOV R8D,0x60`; `14001f274: MOV dword ptr [RSP+0x20],0x20504d40`). The tag constant `0x20504d40` is, in the in-memory little-endian byte order that WinDbg `!pool` displays, the ASCII string `@MP` (bytes `40 4d 50 20`). The tag should be confirmed against a live `!pool` query before being stated as definitive.

The `0x1e` comparison in the prologue requires careful reading. In a Ghidra database with a `DXGKARG_CREATECONTEXT` structure applied to the second argument, the decompiler renders the comparison as:

```c
lVar4._0_4_ = param_2->PrivateDriverDataSize;
lVar4._4_4_ = param_2->Padding2;
if ((lVar4 != 0) && (*(int *)&param_2->hContext != 0x1e)) {
    return -0x3ffffff3;
}
```

The comparison is against the field the applied structure labels `hContext`. Per the documented layout reproduced in Section 4 (`hContext` at offset `0x00`), and per the prologue disassembly (`CMP dword ptr [R14 + 0x20],0x1e`), the value compared against `0x1e` is the 4-byte field at argument offset `+0x20`. Under the documented Microsoft layout, offset `+0x20` is `PrivateDriverDataSize`.

The decompile field names are unreliable here and the structure applied to `param_2` is misaligned relative to the documented `DXGKARG_CREATECONTEXT`, which is why it labels the `+0x20` field as `hContext` (a field the documented layout places at `+0x00`). The raw disassembly is the authority, and it is unambiguous: the dword compared against `0x1e` sits at argument offset `+0x20`, and the read immediately before it (`CMP qword ptr [R14 + 0x18],RDI`) is a non-zero test on the pointer-width field at `+0x18`. Under the documented layout, `+0x18` is `pPrivateDriverData` and `+0x20` is `PrivateDriverDataSize`.

The check is therefore a size check, and an exact-equality one: if `pPrivateDriverData` (`+0x18`) is non-NULL, then `PrivateDriverDataSize` (`+0x20`) must equal exactly `0x1e` (30 bytes), or the call is rejected. It is not a type/version tag. This matters for the dereference-reachability question below: the five blob reads top out at `+0x1d` (byte 29), which is in bounds of a `0x1e`-byte buffer so a buffer too small to satisfy the reads is rejected at this gate, and a buffer of any size other than exactly `0x1e` is rejected.

At first I thought that there are five distinct dereferences of the `pPrivateDriverData` blob at offsets `+0x10`, `+0x14`, `+0x18`, `+0x1c`, and `+0x1d`, but a first automated pass did not reproduce that set and the offset map came back empty (bruh), but that empty result is itself also useful. The extractor's dereference inventory was written to match an _untyped_ decompile: it searched for a local assigned from `param_2[3]`. Run against a database with a struct _applied_, the decompiler emits the field-name form (`param_2->PrivateDriverDataSize`) instead, which that pattern cannot match, so the inventory returned nothing. The reads themselves are present and are read directly from the disassembly. The relevant excerpt:

```c
lVar6 = *(longlong *)&param_2->PrivateDriverDataSize;
/* ... */
if (lVar6 != 0) {
    *(bool *)(puVar10 + 0x56c) = *(int *)(lVar6 + 0x10) != 0;
    *(bool *)((longlong)puVar10 + 0x2b61) = *(int *)(lVar6 + 0x14) != 0;
    FUN_14001fdb0(*(undefined4 *)(lVar6 + 0x18), puVar10 + 0xb,(longlong)puVar10 + 0x5c);
    *(undefined1 *)((longlong)puVar10 + 100)  = *(undefined1 *)(lVar6 + 0x1c);
    *(undefined1 *)(puVar10 + 0x56b) = *(undefined1 *)(lVar6 + 0x1d);
}
```

The reads at `lVar6 + 0x10/0x14/0x18/0x1c/0x1d` are real and gated only by `lVar6 != 0`. And `lVar6` _is_ the `pPrivateDriverData` pointer. This is established by the prologue disassembly, independently of any applied struct. `lVar6` is assigned `*(longlong *)&param_2->PrivateDriverDataSize`; the misapplied struct places its `PrivateDriverDataSize` field at argument offset `+0x18`, which is the low dword of the eight-byte value the prologue tests with `CMP qword ptr [R14+0x18],RDI`. Argument offset `+0x18` is, under the documented `DXGKARG_CREATECONTEXT` layout, exactly `pPrivateDriverData`, and the prologue's non-zero comparison treats `+0x18` as a pointer-width field. So `lVar6` is a read of the documented `pPrivateDriverData` pointer, and the five reads off it are dereferences of the private-data blob. The original "five dereferences" description was correct, for the reason given above...

The reads are now gated by two things, both visible statically: the exact-`0x1e` size check in the prologue, and the `lVar6 != 0` non-NULL test. What static reading cannot settle is whether `lVar6` points into a kernel buffer that `dxgkrnl` sized and owns, or into user-controlled memory and that is the question the rest of this section delves into.

So what does all this say about it? I assume there are two possible runtime behaviors, distinguishable only at runtime. They are recorded here as the point at which static analysis of this DDI reaches its limit.

**Behavior A: raw user pointer reaches the miniport.** If `dxgkrnl` passes the user-mode `pPrivateDriverData` pointer through to `KmCreateContext` without capturing it into a kernel buffer, the `lVar6 + 0x10 … +0x1d` reads in `KmCreateContext` are reads from a user-controllable kernel-mode pointer. In that case, the dereferences would be reading whatever address the user supplied - including, if the user supplied a kernel address, the contents of kernel memory.

**Behavior B: captured buffer; reads stay in bounds.** If `dxgkrnl` captures `pPrivateDriverData` into a kernel pool buffer (the standard Microsoft "Full Capture" pattern), it allocates and copies `PrivateDriverDataSize` bytes. Because the prologue has already forced `PrivateDriverDataSize` to be exactly `0x1e`, that buffer is exactly `0x1e` (30) bytes, and the five reads, topping out at `+0x1d`, byte 29 - fall inside it. Under Full Capture, then, the dereferences are in-bounds reads of a correctly-sized kernel buffer - not a vulnerability on this path.

The two behaviors are mutually exclusive. Settling down between them requires observing the pointer `dxgkrnl` passes to the miniport at the instant of the DDI invocation, a runtime step outside the scope of this post. The static evidence does not stop at the miniport boundary, however: Section 5 traces the `dxgkrnl` side of the same path and establishes which of the two behaviors the static evidence supports.

### 4.2 The structure question: divergence or mis-application?

At the very beginning when I was looking at `KmCreateContext` I thought it accesses a structure that is different from the documented Microsoft `DXGKARG_CREATECONTEXT` layout. That's why I named the structure `INTEL_DXGKARG_CREATECONTEXT_EXT` to mark it as a form of "vendor-extended layout". The evidence gathered after that does not support that conclusion, though.

The table below compares the documented Microsoft layout against the offsets actually seen in `KmCreateContext`'s prologue, as read directly from the disassembly:

|Arg offset|Documented `DXGKARG_CREATECONTEXT` field|Access observed in `KmCreateContext` prologue|
|---|---|---|
|`0x00`|`hContext` (`HANDLE`, `[out]`)|not read in prologue|
|`0x08`|`NodeOrdinal` (`UINT`)|`CMP dword ptr [R14+0x8], EAX` - compared against context-count limit|
|`0x0C`|`EngineAffinity` (`UINT`)|not read in prologue|
|`0x10`|`Flags` (`DXGK_CREATECONTEXTFLAGS`)|-|
|`0x18`|`pPrivateDriverData` (`VOID*`)|`CMP qword ptr [R14+0x18], RDI` - non-zero test on a pointer field|
|`0x20`|`PrivateDriverDataSize` (`UINT`)|`CMP dword ptr [R14+0x20], 0x1e` - compared against `0x1e`|
|`0x24`|`ContextInfo` (`DXGK_CONTEXTINFO`, `[out]`)|written later in the function|

Read this way, the prologue accesses are _consistent_ with the documented layout: a `UINT` at `+0x08` (`NodeOrdinal`), a pointer at `+0x18` (`pPrivateDriverData`), and a `UINT` at `+0x20` (`PrivateDriverDataSize`). No divergence is required to explain them.

The asymmetry found earlier is instead a result of the Ghidra database: the `DXGKARG_CREATECONTEXT` structure type applied to the second argument is misaligned, which is why the decompiler labels the `+0x20` field as `hContext` (a field that the documented layout places at `+0x00`). The decompile field names in the current database are therefore unreliable. (Another reason, to be conformable with reading Assembly as only the raw disassembly can confirm this)

All this is worth writing down, because it changes how the decompile reads. The decompile contains a field it calls `param_2-->pPrivateDriverData` that is only ever bit-tested (`& 3`, `& 0x10`, `>> 4`, `& 1`), never dereferenced as a pointer. By data-flow and by semantics, that mislabelled field is almost certainly the documented `Flags` field at `+0x10`: a `& 0x10` test gating the hardware-queue allocation reads naturally as the `HwQueueSupported` flag bit. The actual `pPrivateDriverData` pointer is the eight-byte value at `+0x18`, which the same misaligned struct surfaces under the name `PrivateDriverDataSize`. The two are cross-wired by the bad struct type; the raw offsets are not affected by it.

The leading-field layout is therefore the standard documented `DXGKARG_CREATECONTEXT`, and the `INTEL_DXGKARG_CREATECONTEXT_EXT` naming is dropped. The trailing region is resolved as well. Re-decompiling `KmCreateContext` with the misapplied structure removed and reading the raw offsets directly, the writes into the output region land exactly on the documented `DXGK_CONTEXTINFO` members and nowhere beyond them:

- `+0x24` `DmaBufferSize` (`0x1000`)
- `+0x28` `DmaBufferSegmentSet` (a segment bitmask)
- `+0x2c` `DmaBufferPrivateDataSize` (`0x1000`)
- `+0x30` `AllocationListSize` (`0xaa`)
- `+0x34` `PatchLocationListSize` (`0xaaa`)
- `+0x3c` `Caps` (the first capability bit, set via `|= 1`).

`DXGK_CONTEXTINFO` is eight `ULONG`s spanning `+0x24` through `+0x43`; the highest offset `KmCreateContext` touches is `+0x3c` (the `Caps` field, ending at `+0x3f`), with `Reserved` (`+0x38`) and `PagingCompanionNodeId` (`+0x40`) left at their post-`memset` zero.

---

## 5. Tracing the call chain through `dxgkrnl`

> **A note on decompiler variable names.** From this section onward, decompiler output uses my explicit renaming convention rather than Ghidra's auto-generated local names. Each renamed variable keeps its original name as a `_PAST<ghidra_name>` suffix, so any renamed variable is traceable back to the raw decompiler output. For the `dxgkrnl` `CreateContext` analysis the mapping is:
> 
> - `local_148` --> `input_struct` - the user-mode `D3DKMT_CREATECONTEXT`
> - `local_138` --> `user_PrivateDriverData_ptr_PASTlocal_138`
> - `local_130` --> `PrivateDriverDataSize_PASTlocal_130`
> - `local_168` --> `kernel_PrivateDriverData_copy_PASTlocal_168`
> - `local_180` --> `created_context_object_PASTlocal_180`
> 
> Excerpts that retain raw `local_NNN` names are unannotated decompiler output reproduced verbatim.

Section 4.1 ended on a question that cannot be settled inside `npu_kmd.sys`: whether `dxgkrnl` captures `pPrivateDriverData` into a kernel buffer before invoking the miniport, or passes the user pointer through. Answering that question required following the call chain from the user-mode `D3DKMTCreateContext` API down into `dxgkrnl.sys`.

The path from user mode to the miniport runs through `D3DKMTCreateContext` (exported by `gdi32.dll`) --> the corresponding syscall stub in `win32k.sys` --> `NtGdiDdDDICreateContext` (the kernel-mode handler in `dxgkrnl.sys`) --> `DXGDEVICE::CreateContext` --> the registered miniport DDI. `NtGdiDdDDICreateContext` calls `DXGDEVICE::CreateContext` directly; the similarly-named `DxgkCreateContextVirtualInternal` / `DxgkCreateContextVirtualImpl` pair belongs to a separate sibling chain that serves the `D3DKMTCreateContextVirtual` entry point, not the non-virtual `D3DKMTCreateContext` path traced here. The chain still spans several stack-argument-heavy calls (which Ghidra's signature recovery reconstructed quite badly), inside which a probe-and-capture step might or might not occur.

![[/assets/img/posts/2026-05-30-reverse-engineering-the-intel-npu-windows-driver-an-mcdm-miniport-architecture-map/20260525183332.png]] _Figure 6 - internal dxgkrnl chain + Full-Capture inset_ (The internal dxgkrnl call chain from NtGdiDdDDICreateContext through DXGDEVICE::CreateContext, with the three-step Full-Capture inset (RtlCopyVolatileMemory -> operator_new[] (DxgK tag) -> memmove) highlighted)

Static analysis of `dxgkrnl!NtGdiDdDDICreateContext` shows three sequential operations on the user input:

1. **Probe-and-copy of the outer struct.** The function clamps the user pointer to `MmUserProbeAddress` and copies 96 bytes (`0x60`) of the `D3DKMT_CREATECONTEXT` structure to a kernel stack frame via `RtlCopyVolatileMemory`. The clamp ensures that a user pointer pointing into kernel address space is replaced by `MmUserProbeAddress` itself before the copy, so the copy cannot dereference kernel memory.
2. **Bounded kernel-pool allocation.** From the kernel-stack copy of the outer struct, the function reads `pPrivateDriverData` and `PrivateDriverDataSize`. If both are non-zero, it allocates a kernel pool buffer with `operator_new[](size, 0x4b677844, 0x100)`. The tag value `0x4b677844` decodes in little-endian as ASCII bytes `44 78 67 4B` = `DxgK`, which is the standard `dxgkrnl`-owned pool tag.
3. **Range-checked copy into the kernel pool.** Before `memmove` runs, the function checks that `user_ptr + size` does not wrap (integer overflow guard) and that the resulting end pointer does not exceed `MmUserProbeAddress` (upper-bound guard). On failure either guard, the function takes an exception path. On success, `memmove(kernel_pool_ptr, user_ptr, size)` copies the user buffer into the kernel pool allocation.

_(The three-step probe --> allocate --> range-checked-copy sequence above is depicted as the highlighted inset of Figure 6.)_

The kernel pool pointer that results from step 2 is then forwarded toward the miniport DDI. The `dxgkrnl` enumeration confirms the capture sequence directly: the verbatim decompiler excerpt shows `_Dst = operator_new[]((ulonglong)PrivateDriverDataSize_PASTlocal_130, 0x4b677844, 0x100)` followed by `memmove(_Dst, user_PrivateDriverData_ptr_PASTlocal_138, …)`, and the callgraph slice confirms `operator_new[]` resolves to `ExAllocatePool2`. The tag `0x4b677844` is `DxgK` in little-endian byte order (`44 78 67 4b`).

The forwarding call into the device-level method is now resolved. The `dxgkrnl` enumeration recovers `DXGDEVICE::CreateContext` at RVA `0x2de368`, and its demangled prototype is:

```
public: long DXGDEVICE::CreateContext(
    class DXGCONTEXT **,                 // [out] created context object
    unsigned int,                        // NodeOrdinal
    unsigned int,                        // EngineAffinity
    struct _D3DDDI_CREATECONTEXTFLAGS,   // Flags
    void *,                              // pPrivateDriverData (the captured kernel-pool pointer)
    unsigned int,                        // PrivateDriverDataSize
    enum _D3DKMT_CLIENTHINT,             // ClientHint
    unsigned char)                       // a byte flag
```

That is eight declared parameters; counting the implicit `this`, the method takes nine arguments.

It is worth noting one tag-disambiguation point for the reader: the `dxgkrnl` capture buffer carries the tag `DxgK` (`0x4b677844`), whereas the per-process VPU context object allocated inside `npu_kmd.sys` (Section 4.1) carries the distinct tag `@MP` (`0x20504d40`). The two tags belong to two different allocations owned by two different components and must not be mixed when reading `!pool` output.

The static evidence therefore shows that on the `NtGdiDdDDICreateContext` path the standard Full Capture pattern is implemented: probe, allocate, range-check, copy, forward kernel pointer. The remaining open question is whether the pointer that reaches the miniport at the moment of the DDI invocation is in fact the kernel-pool pointer produced by this path. That question is settled only by runtime observation of the DDI invocation, which is outside the scope of this static map; Section 7.3 records it as the boundary at which this analysis stops.

---

## 6. Why emulation does not answer the open question

The question Section 5 leaves open is what `dxgkrnl` passes to `KmCreateContext` after the full `NtGdiDdDDICreateContext` path has run, and despite me wanting to, this cannot be settled by emulation. Settling it that way would require emulating, at minimum:

- `dxgkrnl.sys` and its full DDI dispatch machinery
- The MCDM miniport registration handshake, which depends on `dxgkrnl`'s internal state from boot
- The user-mode-to-kernel-mode transition with `pPrivateDriverData` arriving from a real user VA space
- The pool allocator, whose behavior determines whether the captured buffer lands in a region with a recognizable tag
- `MmUserProbeAddress` semantics, which depend on the current process's VA layout and the kernel's mode-switch state

Emulating the NT graphics subsystem to that depth is just too much to a single forwarded-pointer question. The question is one for runtime observation on real hardware, not emulation; Section 7.3 records it as the boundary at which this static map stops.

---

## 7. The static/dynamic boundary

This section explains where static analysis of the `KmCreateContext` path stops. The dynamic phase itself with kernel-debugger observation of the live DDI invocation, will be outside the scope of this blog post.

### 7.1 Locating the loaded binary

On Windows, kernel drivers installed via INF land in `C:\Windows\System32\DriverStore\FileRepository\<package>_<hash>\`, where the hash is per-package. The authoritative location is whatever the running driver service points to:

```powershell
Get-CimInstance Win32_SystemDriver | Where-Object {$_.Name -eq 'npu'} |
    Select-Object Name, PathName, State, Started
```

On the test system this resolves to `C:\WINDOWS\system32\DriverStore\FileRepository\npu.inf_amd64_cdb3a40167d50623\npu_kmd.sys`, version `32.0.100.4621`. The service name is `npu`, not `npu_kmd`: the binary filename and the service name are unrelated, and the INF declares the service name explicitly via the `AddService` directive. `sc query <name>` and many WinDbg conveniences key off the service name.

### 7.3 The unresolved question

- Section 4.1 reduced the `pPrivateDriverData` reads in `KmCreateContext` to a single binary question: does the pointer that reaches the miniport hold a `dxgkrnl`-captured kernel buffer (Behavior B, Full Capture) or the raw user pointer (Behavior A, Pass-Through).
- Section 5 traced the `dxgkrnl` side and found the Full Capture pattern, probe, allocate, range-check, copy, implemented on the `NtGdiDdDDICreateContext` path; the static evidence therefore points to Behavior B. Confirming which pointer actually reaches the miniport at the instant of the DDI call requires runtime observation and is not part of this map.

---

## 8. Scope of this "map"

This section records what the map covers, what is deliberately out of scope, and the questions left open for a follow-on effort.

### 8.1 What the map covers

- Installer structure mapped
- `npu.inf` parsed; service name confirmed as `npu` (binary filename is `npu_kmd.sys`).
- `npu_kmd.sys` identified as an MCDM miniport, not WDM/KMDF. This is the most consequential architectural finding.
- Three platforms supported: VPU 37xx (Meteor Lake), VPU 40xx (Arrow Lake), VPU 50xx (Lunar Lake), distinguished by firmware blobs and PCI IDs.
- DDI callback registration path identified, and the complete `DriverEntry` callback table enumerated: 79 writes in total (one version field, 50 unconditional callback pointers, and 28 build-number-gated pointers), with every offset, target, and gate resolved (Section 3).
- `KmCreateContext` decompiled and annotated as a worked example.
- `DXGKARG_CREATECONTEXT` argument layout cross-referenced against Microsoft documentation; an apparent structural divergence traced to a misaligned Ghidra struct application rather than a confirmed vendor extension, and a struct-removed re-decompile confirmed the trailing region carries no Intel extension. Every write lands inside the documented `DXGK_CONTEXTINFO` (Section 4.2).
- Dereferences inside `KmCreateContext` mapped at `+0x10`, `+0x14`, `+0x18`, `+0x1c`, `+0x1d` relative to the `pPrivateDriverData` pointer.
- The two possible runtime behaviors (Behavior A and Behavior B in Section 4.1) framed and reduced to one observable distinction.
- Inside `dxgkrnl.sys`, `NtGdiDdDDICreateContext` traced through `RtlCopyVolatileMemory` (input-struct probe-and-copy), `operator_new[](size, 0x4b677844, 0x100)` (kernel-pool allocation with `DxgK` tag), and `memmove` (range-checked user-to-kernel copy). The static evidence is consistent with the Full Capture pattern on this path.
- INTEL-SA-01403 (the three "improper conditions check" CVEs patched in `32.0.100.4297`) reviewed as a reference for where new instances of the same class might live.

### 8.2 What is out of scope

Dynamic tests: kernel-debugger observation of the live `KmCreateContext` invocation, and anything that requires the driver to be exercised at runtime is not part of this map. Section 4.1 and Section 5 carry the `pPrivateDriverData` question as far as static analysis allows; Section 7.3 records the boundary.

### 8.3 What the map does not yet cover

The complete callback table is now enumerated in Section 3, but the map stops at the registration layer: it records every populated offset, its target function, and its build-number gating, without resolving which Microsoft DDI role (beyond `DxgkDdiCreateContext` at `_464`) each slot implements. Mapping the remaining offsets onto their `DxgkDdi*` roles, and analysing the individual handlers, is the natural next layer of work.

The following are named here as attack surface but not analyzed in this document:

- the cleanup and error-path handling inside `KmCreateContext`
- the Escape DDI surface
- the behaviour of the 24H2 hardware-scheduling (HWS) callbacks (now enumerated as the build-`24999`-gated slots in Section 3, but not individually analyzed)
- the firmware loader path
- the paging-buffer DDI
- the firmware-blob format.

The installer (`Installer.exe`) and the user-mode DLLs are a separate, user-mode attack surface not examined here.

### 8.4 Open questions

These are the questions that I will consider trying to answer in the future.

1. Does the pointer reaching `KmCreateContext` hold a `dxgkrnl`-captured kernel buffer or the raw user pointer? Section 5 shows the Full Capture pattern on the `dxgkrnl` side; runtime confirmation is the open item.
2. The prologue's exact-`0x1e` size gate (Section 4.1) means a Full-Capture buffer is always 30 bytes and the five reads (max `+0x1d`) are in bounds, so the captured-buffer out-of-bounds question is closed by static analysis.
3. Does the cleanup function handle all partial-initialization states in `KmCreateContext`'s error paths?
4. Where are the `pHwOps` vtable assignment sites that resolve per-generation hardware abstraction?
5. Did `4723` versus `4621` introduce any change in `KmCreateContext` or adjacent functions?
6. Are there DLL hijacking opportunities in `Installer.exe` or any of the user-mode DLLs?
7. Does the firmware loader verify the firmware blob itself, or rely only on the on-disk WHQL signature? If unverified, this is a firmware-integrity gap.

---

## 9. Closing note

The whole idea of this document is the map itself: the identification of `npu_kmd.sys` as an MCDM miniport, the `DriverEntry` callback-registration mechanism, the D3DKMT-to-DDI dispatch path, the `dxgkrnl` trust boundary, and a worked static analysis of one DDI (`KmCreateContext`) carried to the point where static evidence runs out.

Its value is as a reference for anyone auditing this driver, or a comparable MCDM compute miniport.

About the next posts: I love talking about this in the end, because it kinda forces me to not bail out on these ideas, but to actually finish them. So I am looking at several other targets and ideas as well:

- ProGuard Obfuscation and finding your way around it
- Large Lange Model weights forensics and "weights steganography"
- JetBrains _bleeeh ;p_

---

_Offsets in `npu_kmd.sys` version `32.0.100.4723`._ 
Love from [RaptX](https://raptx.org/) 
![[assets/img/posts/2026-05-30-reverse-engineering-the-intel-npu-windows-driver-an-mcdm-miniport-architecture-map/RAPTX-team-logo.png]]