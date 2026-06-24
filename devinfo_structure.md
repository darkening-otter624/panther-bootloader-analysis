# devinfo Partition Structure

Partition: `/dev/block/by-name/devinfo`
Size: 4096 bytes (0x1000)

## Dump Command (requires root)

```bash
dd if=/dev/block/by-name/devinfo of=/sdcard/devinfo.bin
adb pull /sdcard/devinfo.bin
xxd devinfo.bin | head -20
```

## Observed Layout (locked device, firmware v79)

```
Offset  Size  Value       Description
------  ----  ----------  -----------
0x00    4     "OVR0"      Magic / Partition identifier
0x04    2     0x000a      Version (10)
0x06    4     0x8f000000  Checksum
0x0A+   ?     0x00...     Device state fields (all zero = locked/default)
```

## Runtime State

At runtime, the ABL caches the device state in a global variable:

```
dword_DB5A8 (in LinuxLoader address space):
  bit 0 = IsDeviceUnlocked       (sub_3F23C returns this)
  bit 1 = IsDeviceCriticalUnlocked (sub_3F24C returns this)
```

## Related ABL Functions

| Function | Address (v79) | Description |
|----------|---------------|-------------|
| `IsDeviceUnlocked` | `0x3F23C` | Returns `dword_DB5A8 & 1` |
| `IsDeviceCriticalUnlocked` | `0x3F24C` | Returns `(dword_DB5A8 >> 1) & 1` |
| `SetUnlockValue` | `0x408E4` | Sets unlock bit, writes to devinfo |
| `SetUnlockCriticalValue` | `0x409F4` | Sets critical unlock bit, writes to devinfo |
| `PrintDeviceInfo` | `0x5E458` | Prints full device state via fastboot `oem device-info` |

## Notes

- On a locked device the partition is almost entirely zeros after the header
- The full structure of the state fields is not yet mapped (requires comparison with an unlocked unit)
- Writing to this partition without understanding the checksum may cause boot failures
- Even with correct devinfo, XBL enforces signed partition images via efuse — devinfo alone is not sufficient for a real unlock
