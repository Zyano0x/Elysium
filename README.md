# Elysium

<p align="center">
    <img src="https://i.pinimg.com/736x/15/a3/a2/15a3a269ea8112ada7fb7cea433143e7.jpg" alt="Elysium" width="350" />
</p>

**Elysium** is a UEFI bootkit that disables Windows signature checks during boot, allowing unsigned kernel drivers to load by posing as `mcupdate.dll`.

##  Overview

### Idea

A couple of months ago, my friend and I were discussing the possibility of patching certificate validation in **winload.efi** and whether it was even possible. 
Back then, we thought about using it only to load our own driver, but it turned out to open many more opportunities, which I’ll show next.

### Inside winload.efi: Code Integrity

In Windows we had two places where the Drivers are loaded.
First one is winload.efi and second one is ntosrknl.exe.
Here is the hierarchy of drivers based on start type:

| Driver Type     | Start Value | Loaded By         | Notes                               |
| --------------- | ----------- | ----------------- | ----------------------------------- |
| ELAM            | 0 (special) | winload.efi       | Loads **before boot-start drivers** |
| Boot Start      | 0           | winload.efi       | Critical for boot, must be signed   |
| System Start    | 1           | ntoskrnl.exe      | Early kernel initialization         |
| Auto-Start      | 2           | I/O Manager / SCM | After kernel/user init              |
| Demand / Manual | 3           | On request        | Loaded when needed                  |
| Disabled        | 4           | Never             | Not loaded                          |

In winload.efi are loaded the Boot drivers and ELAM driver.
Boot type drivers are loaded in winload.efi using OslLoadDrivers.
This function parses the registry hive SYSTEM (HKLM\SYSTEM\CurrentControlSet\Services).
It enumerated drivers marked with Start = 0 (BOOT_START).
It maps them into memory and prepares their loader data blocks.

In OslLoadDrivers boot type drivers are loaded using OslLoadImage function.
This function is responsible of loading the driver image into memory.
It internally calls LdrpLoadImage then BlImgLoadPEImageEx next ImgpLoadPEImage.

<img src="winload-2.png" width="50%">
<p>

In ImgpLoadPEImage, the function ImgpValidateImageHash is invoked to validate the image hash against the trusted boot policy or the file’s certificate.
We can patch this call to make it skip validation of certificate.

{{< img src="winload-1.png">}}

The other one check in this function is made on checksum to check if the image was tampered.
I have found the exact check in ReactOS sources so u can see how it looks in code.
We can patch this check by this allowing us to patch the binary without need to take care about checksum recalculations.

By these two patches, we are enabling many capabilities.

### 1. Loading Arbitrary Boot Drivers

As this was originally meant, this patch enables loading of drivers regardless of their signature status, including unsigned, test-signed, or expired drivers.
In theory we can also load our own ELAM driver but I have not tested that.
The only requirement that need to be filled is that the driver must start at Boot.

In the project example, I have created a batch script that will automatically create the driver service.
The script configures the driver’s start type as BOOT_START, ensuring it loads during the boot process and the validation of certificate will be made in winload.efi.
Once the script is executed, all you need to do is restart the system, after the reboot, the driver will be executed automatically.

### 2. Boot Drivers Emulation

Here comes the first copability that is not originally meant to exist.
We can replace any already existing boot-start driver with our crafted one.
It allows us to hijack any core boot driver: tcpip.sys, disk.sys, ACPI.sys and others.

Yes, we can hijack any system-critical boot driver, but the challenge is: how can we make the system continue to function without it?

My approach to this problem is Driver Emulation. 
Essentially, we emulate the behavior or functionality of the critical driver to keep the system “breathing.” 
If the system relies on the driver’s exports, we can replicate them; if it relies on specific driver functionality, we can mimic that behavior as well.

#### Staying undetected from ELAM

Yes, we can hijack and emulate any boot-start driver, but this approach can potentially be detected by the ELAM (Early Launch Anti-Malware) driver.
ELAM is designed to check boot-start drivers for common malware signatures and is primary used by the AV software to detect the malware. 
While it should not touch our driver as it is not commonly known threat, in theory, ELAM could notice our invalid certificate in a driver.

So, how can we counter this?
The ELAM driver itself is loaded before any boot-start driver, but there are components that load even earlier. 
One such component is the Microcode Update Library, which I have chosen to target. 
Here, the emulation technique is ideal because this library exposes only a couple of functions that are used by the system and one exported variable. 
By emulating its behavior, we can mimic the original functionality and make the system believe that the update library is operating normally.

The system provides two versions of the microcode update library: one for AMD processors (mcupdate_AuthenticAMD.dll) and one for Intel processors (mcupdate_GenuineIntel.dll).
If we examine the entry of both drivers, we can see that they expose a very similar interface to the operating system:

<div>
    <img src="mc-intel.png" style="width: 50%; float: left;" alt="MC Intel">
    <img src="mc-amd.png" style="width: 50%; float: left;" alt="MC AMD">
</div>
<div style="clear: both;"></div>
<p>

From the perspective of system components, it doesn’t matter which processor is installed; all they need is a consistent interface to perform microcode updates.

In the project example I'm emulating this driver to achive the system execution without issues and arbitary code execution in created thread.
I'm redirecting the interface structure functions to the success ROP gagets, by this allowing to mimic the system that the update functions are working as intended.

The most interesting part is figuring out how to achieve code execution at runtime.
This library executed even before all boot-start drivers, just a few lines after the kernel image itself is loaded.
When this library is executed, we are still running in a firmware context, where memory padding has not yet been allocated and the system is still operating directly on physical memory.
At this point, the AP (Application Processor) cores have not even been started and we are still running solely on the BSP (Bootstrap Processor) core.
Another interesting detail is that this library’s entry is executed three times during the boot process, with two of those calls coming from ntoskrnl.exe.
In theory, we could hook into execution directly from DriverEntry, but I decided to take a different approach.

Instead, I came up with the idea of using one of the functions exposed by this interface to gain execution.
I traced all of these calls to determine which ones are executed during the system boot process, how many times they run, and from where.
Through this analysis, I identified two interface functions that are invoked by ntoskrnl.exe during boot.
One of them, HalpMcUpdateExportData, is called directly by ntoskrnl.exe during its initialization phase.

<img src="ntos-1.png" style="width:60%; float: left;" alt="img">
<div style="clear: both;"></div>

As we can see, ntoskrnl.exe calls the exported function from our interface twice, but only if the first call returns STATUS_BUFFER_TOO_SMALL.
The final problem before achieving runtime code execution is that we cannot simply create a thread from this function. 
At this point, we are still in the early initialization phase of ntoskrnl.exe, where thread-related structures are not yet fully initialized.
However, we can work around this by registering a load image notification callback using PsSetLoadImageNotifyRoutine. 
This callback will be triggered when the first process in the system (typically smss.exe) is loaded. 
From this point onward, it becomes safe to create a thread and continue execution.

U can saw on the video how execution looks like with thread callstack: [Youtube](https://www.youtube.com/watch?v=y7h2q-aL4wE).

### 3. Kernel Binary Backdoor

{{< img src="backdoor.png">}}

Here reveals also one more capability that I have not planned.
We are patching the OslLoadImage function to allow load unsigned and patched images.
The cool part is that the ntoskrnl.exe itself is loaded with this function.
That means we can not only patch the kernel but in theory also hijack/emulate or even faking it.

In our case, since we can patch the kernel binary, I came up with an approach similar to what I used in the Insomnia bootkit.
In Insomnia, we patched the SSDT to redirect calls to our custom payload. Here, we’re taking a slightly different approach.
Specifically, we can patch the SSDT to redirect a user-mode syscall to a different kernel function.
For example, we could make a call to NtShutdownSystem from user-mode instead execute MmCopyVirtualMemory.
If you want to dive deeper into how the SSDT works, you can check out my Insomnia bootkit write-up, where I cover it in much more detail.

In my project example, I created a Python script that parses the PE file’s DIRECTORY_ENTRY_DEBUG to extract the PDB (Program Database) file information.
The script then downloads the corresponding PDB file from Microsoft servers and retrieves the KiServiceTable symbol address.
At runtime, KiServiceTable contains the packed syscall function addresses, while in the raw file it only contains RVA offsets.
The script patches a given syscall function to redirect it to another specified function.
The only requirement is that both the original syscall and the target redirect function must be exported by the PE file.
My script automatically gathers the RVAs from the exports, so both functions need to be exported for the patch to work.

### 4. Kernel Driver Infection

{{< img src="infection.png">}}

Since we can not only hijack but also patch boot drivers, I came up with the idea of infecting them with a crafted image.
I made it as injecting custom image data as shellcode into a newly created section with RWX permissions, then updating the driver’s entry point to our image’s entry.

For this project, I built two components:

1. Infector (user-mode application) – infects a given driver with the payload.
2. Payload (kernel driver) – contains the actual infection execution that runs in the kernel.

The infector hides the driver’s original entry point inside the PE headers, specifically, in OptionalHeader.LoaderFlags. At runtime, we retrieve this value and call the original entry point, preserving normal driver execution.

This approach effectively lets us infect the kernel with a crafted image. In fact, we can go further, the infected driver can host an entire cheat or rootkit that runs directly within it.
And yes, this method can be applied to any boot-start driver to infect it in the same way.
U can saw here on the video how it looks like: [Youtube](https://www.youtube.com/watch?v=ly3BSyPj1wA).
