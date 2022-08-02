# Hashtree Patcher

Hashtree Patcher is an Android command-line tool that patches `vendor_dlkm.img` and `vbmeta.img` for booting without disabling verity.
It also has tools for checking if verity and verification are disabled in the top-level `vbmeta` and if a given partition has an `avb` fs option.

## Usage

```bash
httools patch <partition-name> <partition.img> <vbmeta.img>
```

A hashtree footer is appended to the partition image, and the specified hashtree descriptor in the `vbmeta` image is patched
with the relevant values. Both images are patched in place.

### FEC

If the `fec` binary is present in the working directory, it will be used to generate FEC data. Prebuilt binaries are available
[here](https://github.com/capntrips/vendor_fec/releases/tag/v12.0.0_r12).

```bash
httools avb <partition-name>
```

Checks if the partition has an `avb` fs option, the value of which is printed, if so.

```bash
httools disable-flags
```

Checks if verity or verification are disabled in the top-level `vbmeta`.

```bash
httools mount <partition-name>
```

Mounts the partition, with a hashtree if verity and verification are enabled.

```bash
httools umount <partition-name>
```

Unmounts the partition and tears down its hashtree if verity and verification are enabled.

```bash
httools --version
```

Prints the current version and exits.