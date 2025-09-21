# Kernel Driver Infection

This project demonstrates a method to inject a crafted image into a legitimate kernel driver.

## Components

* **Infector (User-mode app):** Injects the payload into a given driver.
* **Payload (Kernel driver):** Executes the infection logic in the kernel.

## How It Works

1. The infector creates a new RWX section in the target driver.
2. Payload image data is injected as shellcode into this section.
3. The driver’s entry point is updated to point to the injected image.
4. The original entry point is saved in `OptionalHeader.LoaderFlags` and called at runtime to preserve normal driver behavior.

## Usage

```text
Infector.exe <target_driver.sys> <payload.sys> <output_driver.sys>
```

* `<target_driver.sys>` – Legitimate driver to infect.
* `<payload.sys>` – Kernel payload to inject.
* `<output_driver.sys>` – Output infected driver.

## Example

```text
Infector.exe tcpip.sys payload.sys tcpip_infected.sys
```

