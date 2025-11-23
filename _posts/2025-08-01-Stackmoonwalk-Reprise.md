---
title: "Windows Syscalls in 2025: Direct, Indirect, and the Hardware-Assisted Arms Race"
date: 202-11-23 14:20:00 +0100
categories: [Evasion, Malware, Syscalls]
tags: [evasion, malware, system-calls]     # TAG names should always be lowercase
---


## 0. Why syscalls are still the battleground in 2025

On modern Windows, practically every meaningful offensive action eventually goes through a system call:

- allocate / RWX memory  
- write to another process  
- map sections / hollow processes  
- manipulate tokens, registry, file system, and many more.

Historically, defenders sat on the “API” layer: `kernel32.dll`, `kernelbase.dll`, `ntdll.dll`, hook a few  functions, gain visibility into most malicious behaviors. Attackers responded with:

- **Direct syscalls** (SysWhispers, Hell’s Gate, and more): emit the `syscall` instruction yourself, bypassing user-mode hooks.
- **Indirect syscalls**: still use the syscall stub inside `ntdll.dll` but reach it in unintended ways (shadow copies, ROP, or carefully spoofed call stacks).
- **Call stack spoofing / VEH-based tricks**: craft call stacks to fool EDR stack walkers.
- **Dynamic & encrypted syscall stubs**: avoid signatureable patterns in memory.

By 2025, this cat-and-mouse game has moved decisively much *below* simple user-mode hooking:

- Some EDRs intercept syscalls in **kernel-mode**, dump the `KTRAP_FRAME`, and map the saved RIP back to the calling module (like we have seen in Cortex XDR’s `ImageTracker` component). 
- Windows 11 deployments increasingly run with **CET shadow stacks** (user and in some environments kernel) and hardware telemetry (Intel PT / LBR / PMU) feeding EDR analytics engines. 

The result: pure “direct syscall or bust” has become a losing strategy. The meta is now layered:

- Indirect / “recycled” syscalls that preserve plausible call stacks.
- Call-stack spoofing (VEH-based, ROP-less, CET-aware).
- Dynamic, encrypted syscall stubs to resist static + memory scanning.
- Behavioral / kernel / hardware-based detection on the defensive side.

Therefore, the graph now looks less like this :

![usr](https://raw.githubusercontent.com/tlsbollei/tlsbollei.github.io/refs/heads/master/imgs/blog/006Spoofing/usr.png)


But more like this :

![more](https://raw.githubusercontent.com/tlsbollei/tlsbollei.github.io/refs/heads/master/imgs/blog/006Spoofing/more.png)


To understand why, we need to get precise about how syscalls actually work on x64 Windows.

## 1. The x64 syscall pipeline, end-to-end

### 1.1 From `CreateFileW` to `KiSystemCall64`

Let’s follow a boring system call on a 64-bit process on modern Windows 10/11.

**User-mode call chain** (happy path):

```txt
YourCode!DoSomethingCool()
  → kernel32!CreateFileW
      → kernelbase!CreateFileW
          → kernelbase!CreateFileInternal 
              → ntdll!NtCreateFile
                   → ntdll!syscall stub
                       → SYSCALL #NN (SSN) 
```

In a conventional flow, the syscall instruction lives inside ntdll.dll (ntdll!Nt* or Zw* stubs, and for GUI syscalls sometimes win32u.dll). 

That last step in user-mode is the only piece you really need to fake to perform direct syscalls, which is exactly what offensive tools do, and have done for a long time.


### 1.2 The ntdll syscall stub

A typical x64 Nt* stub (heavily simplified) looks like this:

```
NtAllocateVirtualMemory:
    mov     r10, rcx         
    mov     eax, 0x18        
    syscall                  
    ret
```

This is very basic, but given a short introduction to a reader who is new to windows internals :


- RCX is copied into R10 before syscall which is mandated calling convention for the kernel entry stub.
- EAX contains the System Service Number (SSN) which is an index into the SSDT (System Service Descriptor Table) dispatch table.
- Arguments are passed in the usual x64 calling-convention registers / stack, kernel uses the same layout.
- EDRs often hook at this level, what they do is patch the prologue to jump into their proxy, then back into a trampoline. This is the basis of **user-mode hooking**, which includes IAT hooking, inline hooking etc.

### 1.3 SYSCALL entry and the KTRAP_FRAME

On x64, the user to kernel transition is driven by `MSR_LSTAR`, which points to the kernel’s syscall entry, which is usually `nt!KiSystemCall64`.

![cmp](https://raw.githubusercontent.com/tlsbollei/tlsbollei.github.io/refs/heads/master/imgs/blog/006Spoofing/cmp.png)

The KTRAP_FRAME is crucial as it contains the snapshot of the interrupted user-mode context, including the address to resume execution (i.e., the RIP after the syscall instruction). That saved RIP is exactly what some EDRs now use to detect direct syscalls.

### 1.4 Service tables, SSDT and friends

The syscall index (EAX) is used as an index into a service table:

```c
typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PVOID   ServiceTableBase;   // base of array of function pointers 
    PULONG  ServiceCounterTable;
    ULONG   NumberOfServices;
    PUCHAR  ParamTableBase;
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;
```

On x64, the service table is an array of relative offsets from a base, not raw pointers. The dispatcher logic looks something like this, stripped down:

```c
PVOID Base = KeServiceDescriptorTable.ServiceTableBase;
ULONG Index = EAX;    // ssn
PVOID Target = (PUCHAR)Base + (Index * sizeof(ULONG));
Target = (PUCHAR)Base + *(PULONG)Target; // now here goes the real function

// here we jump to target
```

There are multiple service tables (core, GUI, and more), but for syscall evasion the important bit is:

- The mapping from syscall index to kernel routine is stable within a given OS build, but changes between builds.
- Offensive frameworks either ship version-specific tables (SysWhispers2 style) or parse ntdll at runtime to recover indices (Hell’s Gate & friends), and also for example SysWhispers3.

## 2. How defenders instrument syscalls in 2025

### 2.1 User-mode inline hooks (still ubiquitous)

Most EDRs still start in user-mode, as follows:

Inject a sensor DLL into (almost) every process -> patch functions in kernel32.dll / kernelbase.dll / advapi32.dll or ntdll.dll (low-level Nt* calls) -> use inline hooking: overwrite the function prologue with a jump to EDR code.

x64 inline hook demo:

```asm
; original prologue
target:
    push    rbp
    mov     rbp, rsp
    sub     rsp, 0x40
    <continue>

; EDR patched
target:
    mov     rax, <EDR_Proxy>
    jmp     rax
```

and if you are truly against instructions, here is a simplified C-ish view

```c
// Called from patched prologue
void EdrProxy()
{
    // we inspect args such as, call stack, loaded modules, thread token... etc
    if (should_block()) {
        SetLastError(ACCESS_DENIED);
        return;
    }

    // else we return to the original trampoline and continue classic prologue
    return Original_Trampoline();
}
```

This gives us:

- Argument inspection (buffer addresses, sizes, access masks).
- Per-thread context (token, call stack, originating module).
- Optionally, ETW logging, telemetry aggregation, correlation.

As rainbow and sunshine as this approach looks, attackers can rip these hooks out (unhook ntdll, map clean copies, and many more), but that’s exactly what led to the rise of direct syscalls.

### 2.2 Kernel-mode interception via syscall entry

To be resilient to user-mode hook tampering, some products monitor syscalls in kernel-mode.

Lets take Palo Alto’s Cortex XDR approach:

1. A kernel component gets control during the syscall dispatch pipeline.
2. For each syscall, it accesses the built `KTRAP_FRAME` on the current thread’s kernel stack. 
3. It reads the saved user RIP (return address).
4. It resolves that RIP to module path + nearest export using an ImageTracker that tracks module loads/unloads system-wide.
5. If the return address is not inside `ntdll.dll` / `win32u.dll` (so the call didn’t come from the canonical syscall stubs), the event is classified as a direct syscall, because it did not originate from a legitimate context.
6. That event is fed into behavioral analytics and cloud models to determine if the pattern is benign (so legit, like game anti-cheat, security tools) or malicious.

You can visualize the entire process as follows :

![cmpa](https://raw.githubusercontent.com/tlsbollei/tlsbollei.github.io/refs/heads/master/imgs/blog/006Spoofing/compact.png)

The important this is that,

**Even if you completely bypass all user-mode hooks, the kernel can still see who executed the syscall by looking at the saved RIP in KTRAP_FRAME.**

Some other kernel interception mechanisms that we have encountered in the wild included:

- Alt-syscall dispatch, where Windows added PsAltSystemCallDispatch and PsRegisterAltSystemCallHandler to allow alternative syscall handlers, particularly for pico providers. As documented by [Lešnik](https://lesnik.cc/hooking-all-system-calls-in-windows-10-20h1/), these are protected by PatchGuard and intended for tightly controlled internal use.
- ETW-based syscall interception, where past techniques like InfinityHook abused ETW circular kernel logger to intercept syscall dispatch by hijacking timer/performance callbacks. Microsoft hardened this (by protecting relevant structures with PatchGuard and static linking hal.dll). Some variants still exist, but they are very fragile and patch-sensitive.

Commercial EDRs rarely play whack-a-mole with PatchGuard, instead they lean and rely on:

1. Legitimate ETW providers.
2. Syscall filters tied to code integrity / virtualization-based security (VBS).
3. Hardware-backed telemetry, which we will discuss later on.

### 2.3 Call stack inspection and API spoofing detection

Many user-mode hooks don’t simply check arguments, instead they walk the call stack using APIs like `RtlCaptureStackBackTrace` / `StackWalk64` or their own custom unwinding.

Some typical checks deployed are for example:

- Does the immediate caller belong to the same module (like kernelbase calling into ntdll), or some weird RWX region?
- Are there suspicious frames (heap allocations with `PAGE_EXECUTE_READWRITE`, `PAGE_EXECUTE_READ` from anonymous memory, module-less regions)?
- Does the logical call chain (`CreateFileW` -> `NtCreateFile`) match the physical call stack?

If a syscall appears to originate from unbacked memory or from a module that doesn’t usually make such calls, the EDR can treat the event as API spoofing or direct syscall abuse and flag it.

This is the detection logic that VEH-based and call-stack-faking approaches try to break.

### 3. Direct syscalls: Long live SysWhispers, the very noisy animal!

## 3.1 Wut is this?

A direct syscall (in red-team slang) is simply:

1. You set up the registers (EAX = SSN, R10 = RCX, args) yourself.
2. You emit syscall from your own code (or shellcode), in memory that is not the ntdll stub.

```c
__declspec(naked)
NTSTATUS NtAllocateVirtualMemory_Direct(
    HANDLE  ProcessHandle,
    PVOID  *BaseAddress,
    ULONG_PTR ZeroBits,
    PSIZE_T RegionSize,
    ULONG   AllocationType,
    ULONG   Protect
)
{
    __asm {
        mov r10, rcx          
        mov eax, 0x18         ; here we hardcode a random SSN - do not do this, extract dynamically
        syscall
        ret
    }
}
```

Frameworks like SysWhispers2/3 generate hundreds of these stubs with version-aware syscall numbers (SysWhispers2 used to hardcode, SysWhispers3 is smarter and dynamically retrieves SSNs), plus helper code to resolve the correct table per OS build.

What does a defender see?

- The syscall instruction resides in attacker-controlled memory (PE .text (or for that matter any PE struct region) or shellcode region).
- The KTRAP_FRAME’s saved RIP will point back to that region, not to ntdll.
- The call stack above that RIP may show weird frames (like shellcode, packed modules).

### 3.2 Kernel-side detection via KTRAP_FRAME

The Palo Alto / Cortex XDR approach lays out one concrete method, that we have already discussed:

-Hook syscall dispatch at the kernel level.
-For each syscall:

1. Get the pointer to the KTRAP_FRAME
2. Read the Rip field (saved user-mode instruction pointer).
3. Resolve RIP to module using an image tracking subsystem (ImageTracker).
4. If RIP is not in ntdll/win32u and not in a known, benign direct-syscall-using module, mark as direct syscall. 

From this point, cyberdefense products can move into multiple directions:

Events feed into local heuristics (what syscalls? which process? which memory region?).
Events are also aggregated globally to build per-tenant and global baselines of deemed normal direct syscall usage.

This is fundamentally resistant to common methods deployed by sophisticated attackers, such as:

1. Unhooking ntdll.
2. Mapping clean copies, like for example the /KnownDlls/ trick
3. XORing your stubs and decrypting at runtime (the RIP is still where the syscall lives).
4. Shellcoder games like Heaven’s Gate (you’re still executing syscall from non-ntdll memory).

Windows Defender / MDE itself can also use CPU telemetry plus cloud analytics (via Intel TDT) to distinguish weird control-flow from known-good behaviors, even if the direct syscall itself is not explicitly labeled as such.

### 3.3 So.. direct syscalls are dead?

No, but they’re VERY noisy when used in isolation:

Commodity direct-syscall loaders (unmodified SysWhispers + standard injection techniques) are often very trivially detectable by:

- Kernel-mode RIP analysis.
- Stack provenance checks.
- Behavioral analytics (sudden spike of direct syscalls + RWX allocations).

However, targeted offensive tooling, like sophisticated loaders and such, can still squish something out of direct syscalls, given:

- Combined with short-lived usage.
- Embedded into otherwise-trusted modules.
- Layered with call-stack spoofing, indirect syscalls, or hardware-aware behavior.

But, as of 2025,

**Raw direct syscalls from shellcode or obviously unbacked regions are more of a training set for EDR analytics than a reliable stealth technique.**

## 4. Indirect syscalls, direct evolution of Direct Sycalls

### 4.1 Wut are indirect syscalls?

- The syscall instruction still executes inside ntdll.dll / win32u.dll (or occasionally other legit system modules).
- The attacker manipulates how execution reaches that stub:
    1. Jumping into the middle of the stub.
    2. Using jmp / call into a syscall; ret sequence previously laid out by Microsoft.
    3. Leveraging ROP-like sequences that end in syscall without going through a hooked prologue.

- The idea is:
    1. EDR’s kernel-mode detection sees the KTRAP_FRAME.Rip pointing inside ntdll, so it resembles a normal syscall to naive detectors and security products.
    2. User-mode hook detectors that only look for direct syscall from non-system modules miss it.
    3. Stack-walkers may be fooled if the stack is carefully crafted.

### 4.2 Hell’s Gate, Halo’s Gate, Tartarus’ Gate, RecycledGate

These frameworks are often grouped together, and execute as follows:

![aaa](https://raw.githubusercontent.com/tlsbollei/tlsbollei.github.io/refs/heads/master/imgs/blog/006Spoofing/gates.png)



Point is: modern Gate variants are more about resolving correct SSNs and reusing legitimate syscall sites than about unhooking or patching anything.


### 4.3 What defenders see

Even with indirect syscalls:

- Kernel-level detectors that only check “RIP in ntdll?” will be blind, but:
  
    1. Stack-walkers see who called into that stub.
    2. Hardware telemetry (LBR / PT) sees the full branch history (like shellcode -> ntdll!NtAllocateVirtualMemory -> nt!NtAllocateVirtualMemory).

EDRs that track which images normally execute which syscalls can still flag anomalies (so, a random business app executing NtCreateSection thousands of times).

The defensive shift, and fundamental paradigm shift we have seen went from :

“is this a direct syscall?”

To “given the full call stack, LBR, and behavior, does this syscall make sense for this process/module at this time?”

**Indirect syscalls stay useful, but only as part of a larger evasion story.**

## 5. Stack fakery: VEH-based and CET-aware call-stack spoofingň

If defenders walk the stack, attackers try to forge it.

### 5.1 Classic stack-spoofing

Basic approach (high-level):

![spoof](https://github.com/tlsbollei/tlsbollei.github.io/blob/master/imgs/blog/006Spoofing/stackspoof.png)

This can very well fool user-mode EDR hooks that only inspect frames, but:

-  It may break under CET shadow stacks (section 7).
-  Kernel observers still see that code execution came from weird places before hitting ntdll.

With the evolution of cyber defence products, we've seen in the Red Teaming and Malware Development 
community a rise in advanced memory evasion techniques, which aim to bypass the detection of
malicious code by concealing their presence while they reside in the memory of a target process.

Among these techniques, we can find the so-called "Stack Spoofing", which is a technique that
allows to hide the presence of a malicious call in the stack, by replacing arbitrary stack
frames with fake ones.

In this article, we'll present a PoC to implementation of a true dynamic stack spoofer, which will allow us not
only to spoof the call stack to our call, but also to hide the real origin of the call, not only during sleep,
but also during the program execution.

## Overview

The research covered in this article is joint research of **Arash Parsa**, aka [waldo-irc](https://twitter.com/waldo-irc),
**Athanasios Tserpelis**, aka [trickster0](https://twitter.com/trickster012), and me (**Alessandro Magnosi**, aka [klezVirus](https://twitter.com/klezVirus)).

The research was based on the work of [namazso](https://twitter.com/namazso), who has designed 
the original idea behind this technique.

## Introduction

In-depth memory analysis and call stack analysis techniques are technique which have long
been used by Anti-Cheat engines to detect malicious code in memory. Of course, these techniques
are not limited to Anti-Cheat engines, and are slowly being adopted by other security product 
to detect malicious code.

Focusing on the call stack, it's trivial to understand why its analysis can provide anti-cheat engines and EDR products 
with crucial source of telemetry. 
The call stack indeed can provide a security solution with important contextual information regarding 
a function call, including:

* The module that called the current function (i.e., the "original" caller)
* The exact "path" that the call took to reach the current function (i.e., the "call stack", which is tautological)

In this context, we've already seen security products using call stack analysis to detect 
code executed from unbacked memory regions (i.e., not associated with a file on disk), or to enrich 
behavioural analysis by correlating the call stack with the behaviour of the process
(e.g., mapping what module is opening a handle to LSASS).

Even more, the call stack analysis is what security products can use in Userland to detect
indirect system calls made by a process. In this context, the analysis can be done on the call stack 
to see if the process arrived to the system call by calling a high level Windows API 
(e.g., by calling kernel32 CreateThread), if it accessed a native wrapper function directly, 
(e.g., by calling RtlCreateUserProcess), or if it just executed the native function (e.g., 
by calling NtCreateThreadEx), which would show no sign of the call in the call stack.

If you're interested in this kind of analysis, you can check out the following article by [rad98](https://twitter.com/rad9800):

* [Detecting Indirect System Calls in Userland - A Naive Approach](https://fool.ish.wtf/2022/11/detecting-indirect-syscalls.html)

## Previous Research

Stack spoofing is not really a "new" topic, as it has been already used in the past by 
malware authors and game-cheater to hide their presence in the call stack, and bypass 
security solutions that were performing call stack analysis.

Previous research on this topic has been done by [namazso](https://twitter.com/namazso), who has designed and developed 
a technique to [spoof the return address](https://www.unknowncheats.me/forum/anti-cheat-bypass/268039-x64-return-address-spoofing-source-explanation.html) of a function call, which is the address that a function
will return to after it has finished executing. This technique is called "**Return Address Spoofing**".

After that, other researchers have developed similar techniques and PoC to spoof the return address, all based on the 
same, similar idea. Some of the most notable ones are:

* [YouMayPasser](https://github.com/waldo-irc/YouMayPasser) by [waldo-irc](https://twitter.com/trickster012), with accompanying [blog post](https://www.arashparsa.com/bypassing-pesieve-and-moneta-the-easiest-way-i-could-find/). Is a superb PoC tool developed to bypass 
  advanced in-memory scanning tools like [PE-Sieve](https://github.com/hasherezade/pe-sieve) by [hasherezade](https://twitter.com/hasherezade) and [Moneta](https://github.com/forrest-orr/moneta) by [Forrest Orr](https://twitter.com/_ForrestOrr).
* **FOLIAGE/TitanLdr** by **Austin Hudson** (aka **SecIdiot** or **_ilovetopwn**), which was the first public 
  loader to implement sleep encryption and thread stack obfuscation on sleep by cloning another thread context.
  Several commercial tools were largely based on this POC.
* [AceLdr](https://twitter.com/joehowwolf) by [Kyle Avery](https://codemachine.com/articles/x64_deep_dive.html), which is a capable Cobalt Strike Loader that implements Return Address Spoofing 
  and stack obfuscation on sleep. Based on the work by **Austin Hudson**, [namazso](https://twitter.com/namazso), and [waldo-irc](https://twitter.com/trickster012).

<!--
// Edited because this was a controversial PoC. The initial release of the tool was just wrong,
// and he never really tried to fix it, which in turn created a lot of confusion in the community.

// I don't think Mariusz is a bad guy, and he always releases very good material, but not this one. 

// I personally feel that the only contribution that his PoC gave to the community was motivating 
// people to research on the topic.

A stack spoofing PoC that gained huge attention from the community was made by [Mariusz Banach](https://twitter.com/mariuszbit), 
called [ThreadStackSpoofer](https://www.arashparsa.com/bypassing-pesieve-and-moneta-the-easiest-way-i-could-find/). This tool attempted to spoof the call stack of a
thread during sleep. This POC implements a type of stack spoofing known as Stack Truncation, which consist in 
changing the caller address using a trampoline and zeroing out its return address, then restoring it after sleep. 

The major drawbacks of this "call stack hiding" technique are: 

* It will produce a non-unwindable stack (which is an IOC) 
* It doesn't correctly<sup>1</sup> spoof the return address, which will point back to our injected module, 
  which is an IOC as well. 

<sup>1</sup>_Explanation: By using a correct implementation of the "return address spoofing" technique, 
the return address should point a legitimate DLL module, not our injected module/code._
-->

After that PoC was released, [namazso](https://twitter.com/namazso) shared out a better approach [here](https://twitter.com/namazso/status/1442314742488567808), and later [here](https://twitter.com/_Kudaes_/status/1594753842310434816), and lot more research (including ours)
has been done on this topic. Indeed, just in the past few months, other two notable PoC were released:

* [VulcanRaven](https://github.com/WithSecureLabs/CallStackSpoofer) by [William Burgess](https://twitter.com/joehowwolf), which is a PoC that synthetically creates a call stack for a specific thread.
  More information in his article [Spoofing Call Stacks To Confuse EDRs](https://labs.withsecure.com/publications/spoofing-call-stacks-to-confuse-edrs).
* [Unwinder](https://github.com/Kudaes/Unwinder) by [Kurosh Dabbagh](https://twitter.com/_kudaes_), which implements a similar algorithm to the one we implemented to calculate the stack 
frame size and the expected return address. 

Both of the techniques are very good example of call stack spoofing. However, they both have some drawbacks:

* VulcanRaven relies on precomputed call stacks, and on certain specific APIs to build the call stack for a thread
  (i.e., GetThreadContext, SetThreadContext, and CreateThread), which partially limits the usability of the technique.
* Unwinder implements a similar algorithm to the one we implemented to calculate the stack frame size and the expected return address,
  but it doesn't implement the technique that permits to hide the module originating the call.

## Windows x64 Primer

To understand how the dynamic stack spoof technique works, it's important to understand how Windows uses the stack to record
contextual information (i.e., non-volatile registers), how it passes out parameters, and how it sets the return 
pointer to the caller.

### The Windows x64 Stack Frame

Normally, in order to operate, functions need to allocate space on the stack to maintain contextual information,
(i.e., non-volatile registers), define local variables, and, if they need to call a nested function, pad the stack for alignment,
setup input parameter for the nested function, and store the return address before the call is made. We refer to these
functions as "frame" functions.

The recorded information can then be accessed as an offset of RSP:

* Local variables [RSP-X]
* Non-volatile registers [RSP-X]
* Return address of caller [RSP+X]
* Input parameters [RSP+X]

![Windows x86_64 Stack Frame](imgs/blog/006Spoofing/win64_stack_frame.png)

_**Figure 1**: Windows x86_64 Stack Frame (Source: [Windows x64 Calling Convention - Stack Frame](https://www.ired.team/miscellaneous-reversing-forensics/windows-kernel-internals/windows-x64-calling-convention-stack-frame))_

Windows also support the so-called "leaf" functions, which are functions which don't need to allocate a stack frame.
They, of course, have some limitations, like they cannot change non-volatile registers, call other functions, 
and do not have the requirement to operate on an aligned stack.

#### Function Sample

A normal function, which allocates a stack frame, is usually composed by a prologue, a body, and an epilogue:

```asm
; Prologue
mov    [RSP + 8], RCX
push   R15
push   R14
push   R13
mov    RAX,  fixed-allocation-size
call   __chkstk
sub    RSP, RAX
lea    R13, 128[RSP]

; Body
...

; Epilogue
add      RSP, fixed-allocation-size
pop      R13
pop      R14
pop      R15
ret
```

_**Code Snippet 1**: Structure of a function (Source: [MSDOC: Prologue and Epilogue](https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog?view=msvc-170))_


### The Frame Pointer 

If the reader has experience of how things work in Windows x86_32, it's necessary to understand that the 
Windows x86_64 ABI implements a completely different calling convention, which also affects how the stack can be walked back.

In fact, while in Windows x86_32 functions are implemented at the CPU level by using the extended base pointer (EBP), 
which effectively recorded the base of the stack frame (i.e., the return address to the caller), in Windows x86_64 this is 
no longer used. Instead, the Windows x86_64 ABI uses the stack pointer (RSP) both as a stack pointer and a 
frame pointer. Due to the RSP relative addressing, operations that modify the stack pointer (i.e., PUSH, POP, etc.) are usually
limited within a function body and usually reserved for prologue and epilogue codes. There are, of course, some 
exceptions to this general behaviour, such as dynamic stack allocations.

**Important:** In these cases, the value of RSP is stored in RBP before the allocation is made, effectively making RBP 
the frame pointer again. When this behaviour is used, the operation is saved in the `UNWIND_CODE` array with the
opcode `UWOP_SET_FPREG`.

This means that while in X86_32 it was possible to unwind the stack simply by walking back the chain of EBP pointers,
in x64 this is no longer possible. Instead, the x64 architecture uses a different mechanism to unwind the stack,
which is based on information stored in the Runtime Function Table, located in the ".pdata" section of a PE binary.

This table is responsible for storing information about "frame" functions in the executable, including all the 
operations (i.e., UNWIND_CODE structures) that a given function has performed on the stack. This list of instruction
will then be used by the Unwinding algorithm to "rollback" all the operations performed by the function 
on the stack.

![Runtime Exception Table](imgs/blog/006Spoofing/runtime_exception_table.png)

_**Figure 2**: Runtime Exception Table (Source: [Codemachine - Windows x64 Deep Dive](https://codemachine.com/articles/x64_deep_dive.html))_

#### The stack frame size

As we explained before, all the operation that allocate space on  the stack are recorded in the Runtime Function Table
for unwinding purposes. What does it mean to us? Well, it means that we can easily calculate the stack frame size 
using the same information recorded in the table. 

The stack frame size is dependent, of course, on the function, and can be calculated by looping through the `UNWIND_CODE`
array, and summing the allocation space reserved by each of them. For each `UNWIND_CODE` structure, the `OpCode` field
describes the operation that has been performed on the stack, and the `OpInfo` field describes the register involved,
the offset, or the size of the allocation. To make things more difficult, sometimes the size of the allocation is not 
defined in just one `UNWIND_CODE` structure, but in multiple ones.

The full list of `UNWIND_CODE` operation codes can be found in the [MSDN](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170) documentation.

### Why walking the stack back?

The stack unwinding process is necessary for the OS to be able to handle exceptions. 
In fact, when an exception is raised, the OS needs to be able to detect the context whereby the exception was raised,
and operates a set of actions to locate and execute the associated exception handler (if any).

Although a full explanation of the Windows call stack unwinding algorithm is outside the scope of this article, 
it's important to have an idea of how the algorithm works, and why it is important to understand and implement 
stack spoofing.

When an exception is raised, the OS will first try to understand the location, within the function, where the exception
was raised. This is done by searching in the Runtime Function Table for an entry that describes the current function.
This operation can be done by comparing the current RIP with the fields `BeginAddress` and `EndAddress` of each entry in the table.

If a function is found, the Unwind Information is analysed, and the exact location of the exception is determined:
* Epilogue: here we can't have a registered handler, so the epilogue code is simulated, and the process is repeated with the updated RIP
* Prologue: here as well we have no handlers, so the prologue offset is located, and all the unwind-codes from the start to the prolog offset are unwound
* Body: In this case, if present, a language specific handler is invoked. 

At this point the function is either handled by the language specific handler, or the process is repeated 
until a handler is found or the program exits for the unhandled exception.

## The Desync Stack Spoofing Technique

At this point, we should have enough information to start describing the desync stack spoofing technique.

The idea behind this stack spoofing technique is to find suitable stack frames to use as 
ROP gadgets, in order to both desync the unwinding information from the real control flow,
and to hide the real origin of the call.

For this technique to work, we need essentially 4 pieces:

* A first frame, which performs an `UWOP_SET_FPREG` operation, which will set the frame pointer (RSP) to RBP.
* A second frame, which pushes RBP to the stack (`UWOP_PUSH_NONVOL (RBP)`)
* A stack de-synchronization frame, which contains a ROP gadget that will perform the `JMP [RBX]` instruction, which will jump to the real control flow
* A RIP concealing frame, which contains a stack pivot gadget, only useful to conceal our original RIP

To visualize the technique, we will use the following diagram:

![Desync Stack Spoofing](imgs/blog/006Spoofing/stack_spoof_high_level_workflow.png)

_**Figure 3:** High Level Overview of Desync Stack Spoofing Technique_

### Initial setup

This phase is necessary to prepare the necessary registers for the stack spoofing operation.
In particular, we want to save non-volatile registers, and prepare RBX to contain our stack restore function.
Should be something like the following:

```nasm
; Save non-vol registers
mov     [rsp+08h], rbp
mov     [rsp+10h], REG1
mov     [rsp+18h], REG2
...

; Move RBP forward
mov     rbp, rsp

; Creates reference to Restore PROC
lea     rax, Restore
push    rax

; Place the ref in RBX
lea     rbx, [rsp]	
```

### Frames crafting/tampering

After the initial setup, we will craft the stack frames that will be used to perform the stack spoofing.

#### The First Frame (UWOP_SET_FPREG)

As a first frame, we need to find a frame that performs an `UWOP_SET_FPREG` operation. This operation will set the 
frame pointer to a specific offset of the current RSP, storing it in RBP. The operation is performed by a piece of code like the 
following:

```nasm
; Example 1
lea rbp, [rsp+040h]
.setframe rbp, 040h

; Example 2
mov rbp, rsp
.setframe rbp, 0
```

As briefly explained before, this is done to allow modification to RSP within the function body (e.g., for dynamic stack
allocations), without losing the frame pointer value. Worth noticing that it is illegal to modify RSP outside the 
prologue and epilogue, unless the function sets a frame pointer.

Why this frame is necessary? The reason is that by selecting this frame, we can force an arbitrary value to be simulated
as the new Stack Pointer. If this is still not clear, it will become clear in the next section.

#### The Second Frame (UWOP_PUSH_NONVOL)

The second frame is a simple frame that pushes RBP to the stack. This is done by a piece of code like the following:

```nasm
push rbp
.pushreg rbp
```

Why this frame is so important? Alone, this frame is not useful, but combined with the first frame, it will allow us to
put an arbitrary pointer on the stack, which will be used as the simulated Stack Pointer by the unwinding algorithm.

If it's not clear, let's simplify the operations we've seen so far in a single snippet (this is just for the sake of 
explaining the technique, and it should not be considered as a piece of real code):

```nasm
; First Frame 
mov rsp, rbp
.setframe rbp, 0
...

; Second Frame
push rbp
.pushreg rbp
```

From the point of view of the unwinding algorithm, the operations needed to roll back these two frames would be:

```nasm
; Unwinding Second Frame
pop rbp

; Unwinding First Frame
mov rsp, rbp
```

This means, that if we can modify the value of the stack that will be virtually unwound by the algorithm, we can
"force" an arbitrary value to be used as RBP, and therefore as the new Stack Pointer when the First frame is unwound.

In order to link this frame to our original return address (which we want to be `BaseThreadInitThunk`), we need to
force the RBP simulated value to be equal to `_AddressOfReturnAddress()` intrinsic, which would be exactly the 
value we're searching for. 

#### The JMP [RBX] Frame

As we explained before, the `JMP [RBX]` instruction is the JOP gadget that will allow us to de-synchronise the
real control flow from the unwinding, by jumping to the address stored in the RBX register.

This is necessary because, although the first two frames are unwindable because artificially created to be so, they
were not created during execution, and if the program would execute them, it will likely crash.

This frame will be back-linked to the second frame, (meaning this frame return address will be the address of the 
second frame), to ensure the stack is still fully unwindable. However, due to the gadget being executed, the program 
control flow will never reach the return of this function, but will be redirected to whatever contained in RBX, which 
is, as we've explained above, our `Restore` function.

#### The ADD RSP, X Frame

The last piece of the puzzle is the stack pivot gadget, which is used to conceal the original RIP.
This piece is not entirely necessary, but it's useful to hide the `JMP [RBX]` gadget as a return pointer.
The form of this gadget is usually `ADD RSP, X`, where X is the size of the stack frame itself. This gadget
will just deallocate the current stack frame from the stack, and will return to the `JMP [RBX]` gadget.

If you're wondering how to choose X, I would just say that this value is not random, nor a magic number. The
right value for X is a function of (...), well, this is left as an exercise to the reader.

### Restore

After the original control flow has been restored, we need to restore the stack to its original state, and
recover the saved non-volatile registers. The process can be repeated a number of times.

```nasm
; Restore RSP
mov rsp, rbp

; Recover non-volatile registers
mov     rbp, [rsp+08h]
mov     REG1, [rsp+10h]
mov     REG2, [rsp+18h]
...
```

## Demo

You can find the PoC on GitHub, at the following link: [Silent Moonwalk](https://github.com/klezVirus/SilentMoonwalk). The PoC has been released with 
some limitations that requires just a little effort to be overcome, but don't require any more information
than the one contained in this article.

The following video shows the technique in action:

<div class="embed-container">
  <iframe
      style="display: block;margin-left: auto;margin-right: auto;"
      width="800"
      height="600"
      src="https://www.youtube.com/embed/CRCLwP6VDjg"
      frameborder="0"
      allow="autoplay"
      allowfullscreen="">
  </iframe>
</div>


## Thanks

Before ending, I'd like to thank [namazso](https://twitter.com/namazso) for his previous
research on the topic, which I've used extensively for this article, and for his support.

And of course, a huge thanks to my friends and collaborators **Arash Parsa**, aka [waldo-irc](https://twitter.com/waldo-irc) 
and **Athanasios Tserpelis**, aka [trickster0](https://twitter.com/trickster012), without whom this research would not have been 
possible.

## References

* [MSDN: x64 Exception Handling](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170)
* [Codemachine: Windows x64 Deep Dive](https://codemachine.com/articles/x64_deep_dive.html)
