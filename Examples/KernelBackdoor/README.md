# Kernel Binary Backdoor

Emulates patching of the kernel binary at boot to redirect syscalls via SSDT modification.

## Usage

   ```bash
   usage: ssdt_backdoor [-h] --ntoskrnl NTOSKRNL --target-syscall TARGET_SYSCALL --redirect-to REDIRECT_TO [-O OUTPUT]
   ssdt_backdoor: error: the following arguments are required: --ntoskrnl, --target-syscall, --redirect-to
   ```

Required arguments:

* `--ntoskrnl NTOSKRNL` — path to the `ntoskrnl.exe` file to patch.
* `--target-syscall TARGET_SYSCALL` — syscall name to redirect (e.g., `NtShutdownSystem`).
* `--redirect-to REDIRECT_TO` — function to redirect the syscall to (e.g., `DbgPrint`).
* `-O OUTPUT` — (optional) output filename for the patched kernel.

### Example
```bash
python ssdt_backdoor.py --ntoskrnl ntoskrnl.exe --target-syscall NtShutdownSystem --redirect-to DbgPrint
```
After running, replace the original ntoskrnl.exe in the C:\Windows\System32 folder with patched one (take ownership first) and reboot to load the patched kernel.

In the usage project, it shows the example usage of the patch that makes NtShutdownSystem call DbgPrint instead, printing a message.


