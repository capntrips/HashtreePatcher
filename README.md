# Hashtree Patcher

Hashtree Patcher is an Android command-line tool that patches `vendor_dlkm.img` and `vbmeta.img` for booting without disabling verity.
It also has tools for checking if verity and verification are disabled in the top-level `vbmeta` and if a given partition has an `avb` fs option.

## Usage

```bash
httools patch <vendor_dlkm.img> <vbmeta.img>
```

A hashtree footer is appended to the `vendor_dlkm` image, and the `vendor_dlkm` hashtree descriptor in the `vbmeta` image is patched
with the relevant values. Both images are patched in place.

### FEC

If the `fec` binary is present in the working directory, it will be used to generate FEC codes. Prebuilt binaries are available
[here](https://github.com/capntrips/vendor_fec/releases/tag/v12.0.0_r12).

```bash
httools avb <partition-name>
```

Checks if the given partition has an `avb` fs option, the value of which is returned, if so.

```bash
httools disable-flags
```

Checks if verity and verification are disabled in the top-level `vbmeta`.