# Meta Quest 3S (Panther) Bootloader Research

> Research conducted on a Meta Quest 3S (codename: **panther**) running firmware **v79** (last version supported by the FreeXR root exploit).

---

## Background

More and more bootloader-unlocked Quest 3/3S units have been appearing on secondhand markets (notably eBay, seller: FlipNE, UK-based). These are **not** the result of any software exploit — they are factory/engineering sample units leaking out of the supply chain, sold headset-only without controllers.

Key observations:
- These units cannot play most online games (Meta's backend attestation/integrity checks flag them)
- They are useful for root on latest firmware since there are no system integrity checks to fight
- There is **no** publicly known software method to unlock the bootloader on Quest 3/3S as of v79
- The FreeXR root exploit (CVE-2025-21479, Adreno GPU driver memory corruption) provides **temporary** kernel r/w and SELinux disable, but does NOT unlock the bootloader

---

## Device Info

| Field | Value |
|-------|-------|
| Device | Meta Quest 3S |
| Codename | panther |
| Firmware | v79 (last FreeXR-rootable version) |
| SoC | Snapdragon SM8550 |
| Architecture | ARM64 |
| ABL Build | DEBUG_CLANG35, edk2-3 (Qualcomm fork) |
| OpenSSL version | 1.1.1d (embedded in ABL) |

---

## ABL Extraction

The Android Bootloader (ABL) lives in the `abl_a` / `abl_b` partitions (A/B slot scheme).

```bash
# requires root (via FreeXR exploit)
dd if=/dev/block/by-name/abl_a of=/sdcard/abl.img
adb pull /sdcard/abl.img
```

The image is LZMA-compressed inside a UEFI firmware volume. Extract with [imjtool](http://newandroidbook.com/tools/imjtool.html):

```bash
chmod +x imjtool.ELF64.x64
./imjtool.ELF64.x64 abl.img extract 0
# produces: extracted/LinuxLoader (PE32+ ARM64 EFI binary)
```

Full partition list of interest:
```
abl_a / abl_b       - Android Bootloader
xbl_a / xbl_b       - Qualcomm XBL (first stage, fuse-enforced)
vbmeta_a / vbmeta_b - Verified Boot metadata
devinfo              - Device state (locked/unlocked flags)
unlock_token         - Unlock token storage
```

---

## ABL Internals

The extracted `LinuxLoader` binary is a single PE32+ EFI application containing:
- Fastboot implementation
- AVB (Android Verified Boot) stack
- Unlock token verification
- Device info read/write
- OpenSSL 1.1.1d (statically linked)

Build path leaked via debug strings:
```
/data/sandcastle/boxes/trunk-grepo-oculus-grepo-12/bootable/bootloader/edk2-3/
```

---

## Unlock Mechanism

### Overview

The unlock flow is gated by three things:
1. A valid signed unlock token (software)
2. Device serial number match (software)
3. Hardware efuse (OEM_PK_HASH) enforcing XBL/ABL signing (hardware)

### Key Functions (IDA offsets in LinuxLoader)

| Address | Function | Description |
|---------|----------|-------------|
| `0x64734` | `VerifyUnlockToken` | Main token verification entry point |
| `0x66878` | `PKCS7Verify` | PKCS7 signature verification wrapper |
| `0x678CC` | `LoadTrustedKey` | Loads Meta's embedded public key |
| `0x5C9BC` | `FastbootCmdHandler` | Handles `oem unlock` / `unlock_token` fastboot commands |
| `0x5B738` | `CheckUnlockAllowed` | Checks `IsAllowUnlock`, token timestamp, reboot count |
| `0x64F84` | `ParseBootloaderScript` | Parses the unlock token script format |
| `0x63570` | `DoUnlock` | Actually performs the unlock (writes devinfo) |
| `0x3F23C` | `IsDeviceUnlocked` | Returns `dword_DB5A8 & 1` |
| `0x3F24C` | `IsDeviceCriticalUnlocked` | Returns `(dword_DB5A8 >> 1) & 1` |
| `0x408E4` | `SetUnlockValue` | Writes unlock state to devinfo |
| `0x409F4` | `SetUnlockCriticalValue` | Writes critical unlock state to devinfo |

### Unlock Token Format

The token is a PKCS7 signed blob containing a "bootloader script" with typed records:

| Record Type | Meaning |
|-------------|---------|
| `0x02` | Unlock type (0 = normal, 1 = critical) |
| `0x03` | End of script |
| `0x0A` | Timestamp (8 bytes, little-endian uint64) |
| `0x0B` | Reboot count (4 bytes) |

The script must be signed with Meta's private key. The serial number embedded in the token must match the device's serial number (`sub_4CBFC` performs this check).

### Unlock State Storage

The locked/unlocked state is stored in the `devinfo` partition:

```
Offset 0x00: "OVR0"        - magic
Offset 0x04: 0x000a        - version
Offset 0x06: checksum
Offset 0x08+: device state fields (all zero on locked device)
```

At runtime, the unlock state is cached in `dword_DB5A8`:
- Bit 0: device unlocked
- Bit 1: device critical unlocked

---

## Meta's Embedded Public Key

Found at offset `0xA85B3` in `LinuxLoader`, referenced directly by `sub_64734`.

**Format:** RSA SubjectPublicKeyInfo (DER encoded, 292 bytes)

**Parameters:**
- Key size: **2048-bit**
- Public exponent: **e=3**

```
Modulus:
00:ad:62:26:d8:2f:f4:72:d3:1b:fa:8d:98:17:e3:
c4:3c:8b:f6:5a:0e:83:5a:4f:01:87:ed:67:4f:76:
6f:92:7e:fe:14:f2:ed:bf:6d:22:a8:e5:35:9f:7e:
f8:c5:71:16:e6:19:ce:4e:ce:e2:7b:93:68:70:87:
22:6f:c2:d1:e4:0c:dd:18:cc:fa:f5:9e:bb:3b:54:
e5:63:d4:11:e2:af:12:46:b3:41:26:fd:3b:39:09:
c2:b8:17:0d:a0:40:14:81:3c:d5:ae:f9:51:e2:56:
59:1f:34:99:dc:f3:a7:8d:18:3b:88:ed:fe:1d:68:
39:e8:8c:b5:92:ec:70:da:1c:ac:a8:9d:82:43:2f:
97:d8:ca:87:33:c3:90:2f:1f:42:b4:b8:e8:b9:2e:
da:8e:19:3f:b0:c0:01:c3:a1:37:44:c2:4a:c4:c6:
a3:02:90:a1:ca:28:5e:5f:37:45:8a:5a:cb:30:ff:
ce:c3:3f:55:9b:60:b6:06:49:18:d6:84:09:4b:fd:
3d:a7:e3:ff:d1:21:78:a6:de:71:12:13:b5:57:bd:
76:ca:12:18:68:3a:1d:70:f2:2b:a9:27:60:f6:f6:
a2:1e:fc:bf:1d:1d:64:91:d3:32:ab:be:cf:f7:39:
08:9f:06:c0:88:40:0c:c8:6e:a4:ef:1e:e2:fc:7b:
15:c7
Exponent: 3 (0x3)
```

### Cryptographic Analysis

The use of **e=3** is a known weak choice. Classic attacks:

- **Cube root attack** (Coppersmith): applicable to RSA e=3 with no/weak padding. If the message M is small enough, `C = M^3 mod N` means you can recover M by taking the integer cube root of C directly.
- **Bleichenbacher 2006 signature forgery**: applicable to PKCS1v1.5 with e=3 if the verifier doesn't check padding all the way to the end of the block.

However, padding analysis of `sub_64734` and `sub_67B28` shows:
- Outer PKCS7 wrapper: **PKCS1v1.5** (`0x6688C`, `0x66A90`)
- Inner signature verification: **PSS padding** (`0x648FC`, `0x678CC`, `0x67998`, `0x679B0`)

**PSS with e=3 is not vulnerable to the classic forgery attacks.** The cube root and Bleichenbacher attacks do not apply to PSS. The cryptographic protection is therefore sound despite the weak exponent choice.

---

## Hardware Root of Trust

The fundamental barrier to bootloader unlocking is the **OEM_PK_HASH efuse** (eFuse blown at the factory):

- XBL (first stage bootloader) verifies ABL signature against the fused key hash on every boot
- Even if devinfo is modified to show "unlocked", XBL will reject any unsigned/differently-signed partition images
- Patching the ABL binary on-disk (`abl_a`) would require the modified ABL to be signed with Meta's private key to survive XBL verification
- Without Meta's private key, any modification to `abl_a` results in a **permanent hard brick** with no recovery path

---

## Potential Attack Vectors

### 1. Runtime Memory Patch (No brick risk, non-persistent)
With kernel r/w from FreeXR, patch `sub_66878` return value in memory to always return 1 (success). However, ABL runs **before** Android boots and is not resident in memory by the time root is available. The patch window does not exist in normal boot flow.

### 2. devinfo Partition Modification (Brick risk if checksum enforced)
Flip the unlock bit in the `devinfo` partition directly via `dd`. Even if successful, XBL/ABL would still reject unsigned partition flashes, limiting the usefulness.

### 3. Voltage Glitching
Mentioned by FreeXR admins as a known method: requires reballing a memory chip, ~30 minutes of glitching for temporary root. Extremely invasive, not practical for most users.

### 4. Supply Chain Units
Bootloader-unlocked units (presumably with efuse in dev/unlocked state) are leaking from Meta's supply chain/refurb pipeline. Observed being sold on eBay UK by seller "FlipNE" for ~£100-110 headset-only. These run older firmware (observed: v71) and cannot be updated past their current version without losing the unlock.

### 5. Private Key Compromise
If Meta's RSA-2048 private key (corresponding to the embedded public key) were ever leaked or compromised, valid unlock tokens could be generated for any device. Currently not feasible.

---

## IDA Python Scripts

### Find embedded DER certificates
```python
import idc
import idautils
import idaapi

def find_der_certs(min_size=100):
    for seg in idautils.Segments():
        ea = idc.get_segm_start(seg)
        end = idc.get_segm_end(seg)
        while ea < end:
            b0 = idc.get_wide_byte(ea)
            b1 = idc.get_wide_byte(ea + 1)
            if b0 == 0x30 and b1 == 0x82:
                size = (idc.get_wide_byte(ea + 2) << 8) | idc.get_wide_byte(ea + 3)
                if size > min_size:
                    print(f"DER blob @ 0x{ea:X}, size: {size+4} bytes")
                    for xref in idautils.XrefsTo(ea):
                        func = idaapi.get_func(xref.frm)
                        if func:
                            print(f"  xref: {idc.get_func_name(func.start_ea)} @ 0x{func.start_ea:X}")
            ea += 1

find_der_certs()
```

### Find unlock/auth related functions
```python
import idc
import idautils
import idaapi

keywords = [b'unlock', b'token', b'verify', b'sign', b'auth', b'flashing']

for s in idautils.Strings():
    content = str(s)
    if any(k.decode() in content.lower() for k in keywords):
        print(f"0x{s.ea:X}: {content}")
        for xref in idautils.XrefsTo(s.ea):
            func = idaapi.get_func(xref.frm)
            if func:
                print(f"  referenced in: {idc.get_func_name(func.start_ea)} @ 0x{func.start_ea:X}")
```

### Dump Meta's public key
```python
import idc

ea = 0xA85B3
b2 = idc.get_wide_byte(ea + 2)
b3 = idc.get_wide_byte(ea + 3)
size = (b2 << 8) | b3
total = size + 4

data = bytes([idc.get_wide_byte(ea + i) for i in range(total)])
with open('/tmp/meta_unlock_pubkey.der', 'wb') as f:
    f.write(data)
print(f"dumped {total} bytes")
```

Then inspect with:
```bash
openssl pkey -in /tmp/meta_unlock_pubkey.der -inform DER -text -noout -pubin
```

---

## Fastboot OEM Commands

Full list of OEM fastboot commands found in the ABL:

```
oem device-info
oem disable-charger-screen
oem disable-dload-mode
oem disable-factory-mode
oem disable-linux-console
oem enable-charger-screen
oem enable-dload-mode
oem enable-factory-mode
oem enable-linux-console
oem enable-ramdump
oem factory-reset
oem get-kernel-flavor
oem get-pstore-record
oem lock
oem lock critical
oem lock no-format
oem off-mode-charge <0|1>
oem partition-info <partition>
oem read-persist
oem reboot-edl
oem reboot-sideload
oem reset-devinfo
oem reset-rollback
oem select-display-panel
oem selinux
oem set-appended-cmdline <string>
oem set-enable-adb-on-retail <0|1>
oem set-in-qalab-environment
oem set-production-mode
oem set-retail-device <0|1>
oem set-sensorlock <0|1>
oem set-serial-number <serial number>
oem set-sideload-downgrade-allow <0|1>
oem set-titan-mode <0|1>
oem set-verified-boot <0|1>
oem set-verify-arb-version <0|1>
oem set-verity <0|1>
oem sha1 <partition> <size>
oem shutdown
oem unlock
oem update-all-slots
oem write-persist
```

Notable: `oem set-in-qalab-environment` suggests Meta has internal QA lab devices with different trust levels.

---

## Conclusion

A full bootloader unlock on Quest 3S without a factory-unlocked unit requires either:
- Meta's RSA-2048 private key (for token generation)
- A hardware glitching attack on the efuse reading circuit
- A vulnerability in XBL itself (no known public vuln)

The software unlock verification is well-understood and fully documented here. The cryptography (RSA-2048 PSS) is sound. The real barrier is hardware.

---

## Credits

- **FreeXR** - CVE-2025-21479 root exploit for Quest 3/3S
- **QuestEscape** - Prior bootloader research
- **darknight1050** - Quest 1/2 bootloader unlocker (CVE-2021-1931)
- **Christopher Wade / Pentestpartners** - Original EDK2 fastboot buffer overflow research

---

*Research conducted on firmware v79 (panther/Quest 3S). Offsets may differ on other firmware versions.*
