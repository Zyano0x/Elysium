# Microcode Library Emulation

Emulates the boot-time microcode update library. The OS continues to operate normally while we hijack its exported interface to run code early in the boot process. A load-image notification is registered, and a real thread is created only after the first user-mode process loads.

### Usage

1. Change the project build configuration to match your CPU vendor (AMD or Intel).
2. Compile the project.
4. Take ownership of the original `mcupdate_*.dll` file in `System32` folder and replace with your compiled version.
5. Reboot the system. 

The emulated microcode library executes **during the boot process**, and at runtime you should see the `DbgPrint` messages.
