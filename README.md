# Hashtree Patcher

Hashtree Patcher is an Android command-line tool that patches `vendor_dlkm.img` and `vbmeta.img` for booting without disabling verity.

## Usage

```bash
hashtreepatcher <vendor_dlkm.img> <vbmeta.img>
```

A hashtree footer is appended to the `vendor_dlkm` image, and the `vendor_dlkm` hashtree descriptor in the `vbmeta` image is patched
with the relevant values. Both images are patched in place.

### FEC

If the `fec` binary is present in the working directory, it will be used to generate FEC codes. Prebuilt binaries are available
[here](https://github.com/capntrips/vendor_fec/releases/tag/v12.0.0_r12).