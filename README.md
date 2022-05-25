# Hashtree Patcher

Hashtree Patcher is an Android command-line tool that patches `vendor_dlkm.img` and `vbmeta.img` for booting without disabling verity.

## Usage

```bash
hashtreepatcher <vendor_dlkm.img> <vbmeta.img>
```

A hashtree footer is appended to the `vendor_dlkm` image, and the `vendor_dlkm` hashtree descriptor in the `vbmeta` image is patched
with the relevant values. FEC codes are no generated. Both images are patched in place.