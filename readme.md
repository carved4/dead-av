# dead-av 
a golang implementation of bring-your-own-vulnerable-driver (byovd) attack using the bdapiutil64.sys driver to terminate security software processes. this is a rewrite and expansion of the original implementation from [blacksnufkin/byovd/bdapiutil-killer](https://github.com/BlackSnufkin/BYOVD/tree/main/BdApiUtil-Killer).

## demo 
<img width="579" height="763" alt="image" src="https://github.com/user-attachments/assets/87fdaf3f-5768-45b4-a316-5770621d8094" />

## what it does

this tool exploits vulnerabilities in the bitdefender api utility driver (bdapiutil64.sys) to gain kernel-level process termination capabilities. it automatically:

- embeds and extracts the vulnerable driver
- installs the driver as a windows service
- continuously scans for security software processes
- terminates detected processes using kernel-level ioctl calls
- targets 441 security products including edr, antivirus, and monitoring tools

## how it works

### driver exploitation
the tool leverages multiple vulnerabilities in bdapiutil64.sys:
- **arbitrary process termination** via ioctl code `0x800024b4`
- **controllable process handles** through `obopenbjectbypointer`
- **arbitrary memory read/write** through various ioctl codes
- **file creation with controllable objectname** via `iocreatefile`

### attack flow
1. extracts embedded vulnerable driver to filesystem
2. creates and starts driver service using windows service control manager
3. opens handle to driver device (`\\.\\bdapiutil`)
4. enumerates running processes using `createtoolhelp32snapshot`
5. for each target process found:
   - sends pid to driver via `deviceiocontrol` with ioctl `0x800024b4`
   - driver terminates process at kernel level
6. repeats scan every 2 seconds

### targeted software
covers major security vendors:
- **microsoft defender** (msmpeng.exe, mpcmdrun.exe, nissrv.exe)
- **crowdstrike falcon** (csfalconservice.exe, csfalconcontainer.exe)
- **sentinelone** (sentinelagent.exe, sentinelhelperservice.exe)
- **carbon black** (cb.exe, cbcomms.exe, cbstream.exe)
- **symantec** (ccsvchst.exe, nortonsecurity.exe, sepmaster.exe)
- **kaspersky** (avp.exe, avpui.exe, klnagent.exe)
- **trend micro** (tmbmsrv.exe, tmccsf.exe, tmlwfmgr.exe)
- **bitdefender** (bdagent.exe, vsserv.exe, bdservicehost.exe)
- **malwarebytes** (mbamservice.exe, mbamtray.exe)
- **analysis tools** (processhacker.exe, procexp.exe, wireshark.exe)
- **and 500+ more processes**

## usage

```bash
# compile
go build -o dead-av.exe cmd/main.go

# run (requires administrator privileges)
./dead-av.exe
```

the tool requires administrator privileges


### exploitation vectors for this driver

#### 1. arbitrary process termination
```json
{
  "title": "arbitrary process termination",
  "description": "zwterminateprocess - handle controllable",
  "eval": {
    "IoControlCode": "0x800024b4",
    "InputBufferLength": "0x4"
  }
}
```

#### 2. memory read/write primitives
```json
{
  "title": "read/write controllable address",
  "description": "read",
  "eval": {
    "IoControlCode": "0x800021a0",
    "InputBufferLength": "0x10"
  }
}
```

#### 3. file system manipulation
```json
{
  "title": "ObjectName in ObjectAttributes controllable",
  "description": "IoCreateFile",
  "eval": {
    "IoControlCode": "0x8000264c",
    "InputBufferLength": "0x208"
  }
}
```

## credits

original implementation and vulnerability research by [@blacksnufkin](https://github.com/BlackSnufkin/BYOVD/tree/main/BdApiUtil-Killer). this is a golang rewrite with additional features including:
- embedded driver extraction
- expanded process targeting
- kernel module enumeration + get ntsokrnl base


