# Elysium

<p align="center">
    <img src="https://i.pinimg.com/736x/15/a3/a2/15a3a269ea8112ada7fb7cea433143e7.jpg" alt="Elysium" width="350" />
</p>

**Elysium** is a UEFI bootkit that disables Windows signature checks during boot, allowing unsigned kernel drivers to load by posing as `mcupdate.dll`.

##  Overview

Elysium targets `winload.efi` during early boot, locating and modifying the `ImgpLoadPEImage` routine responsible for loading PE images and verifying their integrity. By doing so, it effectively disables image integrity validation, allowing to load modified binaries of trusted modules even if it is kernel itself. Project itself is made with concept of loading the unsigned drivers as trusted module `mcupdate.dll`.

###  Features

-  UEFI bootkit binary is only 1.4 kb in size
-  Patches signature verification in `ImgpLoadPEImage`
-  Loads unsigned drivers as signed (e.g., `mcupdate.dll`)
-  Bootkit will be automatically unloaded after boot process end.

## About Opportunities and Impact

The project not only allows loading unsigned drivers as `mcupdate.dll`, but also disables the entire signature verification system-wide.
This opens up many possibilities.

### Faking the Kernel

We can abuse this to force the system to load a modified version of `ntoskrnl.exe`.
This allows us to patch functions used by security solutions to scan system integrity.
We can even replace the entire kernel with a fake one, perform arbitrary operations, and then pass execution back to the original kernel.
The only limit is your imagination.

### Backdoors

We can introduce small modifications into trusted modules accessible from user mode, effectively creating stealthy backdoors with nearly unlimited potential.

## Usage

* Select `INTEL` or `AMD` solution configuration depends on your system
* Compile solution
* Copy compiled `bootx64.efi` binary to the USB drive under the `EFI\Boot\` directory (e.g. `F:\EFI\Boot\bootx64.efi`)
* Replace the original `mcupdate.dll` file in `C:\Windows\System32\` with the compiled one (you may need to take ownership of the file)
* Reboot and boot from the USB drive

ATTN: If something goes wrong, you may be unable to boot into Windows. Make sure you have a way to restore your system state.

## Compatibility

The project has been tested on both physical and virtual machines running `Windows 10 22H2`.
Other versions of Windows may have compatibility issues.

## Patch Details

```asm
jz short loc → jmp short loc
````

```asm
call ImgpValidateImageHash → xor eax, eax; nop; nop; nop
```
