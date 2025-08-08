package kernel

import (
	"fmt"
	"strings"
	"unsafe"

	"github.com/carved4/go-wincall"
	winapi "github.com/carved4/go-native-syscall"
)

const (
	SystemModuleInformation  = 11
	GENERIC_READ             = 0x80000000
	GENERIC_WRITE            = 0x40000000
	OPEN_EXISTING            = 3
	FILE_ATTRIBUTE_NORMAL    = 0x80
	INVALID_HANDLE_VALUE     = ^uintptr(0)
	MAX_MODULE_NAME          = 256
)

type KernelModule struct {
	BaseAddress uintptr
	Size        uint32
	Name        [MAX_MODULE_NAME]byte
}

func Call(dllName, funcName string, args ...interface{}) (uintptr, error) {
	moduleHash := wincall.GetHash(dllName)
	moduleBase := wincall.GetModuleBase(moduleHash)
	if moduleBase == 0 {
		moduleBase = wincall.LoadLibraryW(dllName)
	}
	
	result, err := wincall.Call(dllName, funcName, args...)
	return result, err
}

func GetKernelModuleBase(devicePath, moduleName string) (uintptr, error) {
	bufferSize := uintptr(64 * 1024) 
	buffer := make([]byte, bufferSize)
	
	ret, err := winapi.NtQuerySystemInformation(
		uintptr(SystemModuleInformation),
		unsafe.Pointer(&buffer[0]),
		bufferSize,
		&bufferSize)
	
	if ret == 0xC0000004 { 
		if bufferSize == 0 {
			return 0, fmt.Errorf("returned buffer size is 0")
		}
		buffer = make([]byte, bufferSize)
		ret, err = winapi.NtQuerySystemInformation(
			uintptr(SystemModuleInformation),
			unsafe.Pointer(&buffer[0]),
			bufferSize,
			&bufferSize)
	}
	if ret != 0 {
		return 0, fmt.Errorf("NtQuerySystemInformation failed, status: 0x%X, err: %v", ret, err)
	}
	// Parse the returned data
	if len(buffer) == 0 {
		return 0, fmt.Errorf("buffer is empty after NtQuerySystemInformation")
	}
	
	if len(buffer) < 8 {
		return 0, fmt.Errorf("buffer too small: %d bytes (need at least 8)", len(buffer))
	}
	
	// The actual structure is different - it starts with ULONG count, not ULONG_PTR
	numberOfModules := *(*uint32)(unsafe.Pointer(&buffer[0]))
	offset := uintptr(4) // Skip the ULONG count
	
	targetModule := strings.ToLower(moduleName)
	
	// Parse each module entry
	fmt.Printf("[+] found %d kernel modules:\n", numberOfModules)
	fmt.Printf("[+] first 64 bytes of buffer after count:\n")
	for i := 0; i < 64 && i < len(buffer)-4; i += 8 {
		fmt.Printf("[+] offset %d: %02X %02X %02X %02X %02X %02X %02X %02X\n", 
			i+4, buffer[i+4], buffer[i+5], buffer[i+6], buffer[i+7], 
			buffer[i+8], buffer[i+9], buffer[i+10], buffer[i+11])
	}
	
	for i := uint32(0); i < numberOfModules && i < 5; i++ { 
		if offset+288 > uintptr(len(buffer)) { 
			fmt.Printf("[-] module %d: offset too large (%d > %d)\n", i, offset+288, len(buffer))
			break
		}
		
		// offset 20-27: 00 00 60 6F 06 F8 FF FF = ImageBase
		// offset 28-31: 00 60 04 01 = ImageSize  
		// offset 44-45: 01 00 = NameOffset
		// offset 46-47: 15 00 = ?
		// offset 48+: 5C 53 79 73... = "\Sys..." 
		
		fmt.Printf("[+] module %d raw data at offset %d:\n", i, offset)
		
		imageBase1 := *(*uintptr)(unsafe.Pointer(&buffer[offset+16])) 
		imageBase2 := *(*uintptr)(unsafe.Pointer(&buffer[offset+20])) 
		
		fmt.Printf("[+] - trying ImageBase at offset+16: 0x%X\n", imageBase1)
		fmt.Printf("[+] - trying ImageBase at offset+20: 0x%X\n", imageBase2)
	
		for nameStart := uintptr(40); nameStart <= 50; nameStart++ {
			namePtr := offset + nameStart
			if namePtr < uintptr(len(buffer)) && namePtr+50 < uintptr(len(buffer)) {
				nameBytes := buffer[namePtr:]
				var nameEnd int
				for j, b := range nameBytes {
					if b == 0 || j >= 100 {
						nameEnd = j
						break
					}
				}
				
				if nameEnd > 5 { 
					name := string(nameBytes[:nameEnd])
					
					if strings.Contains(name, "\\") || strings.Contains(name, ".") {
						fmt.Printf("[+] - found name at offset+%d: '%s'\n", nameStart, name)
						
						
						if strings.Contains(strings.ToLower(name), "ntoskrnl") {
							return imageBase2, nil
						}
						break 
					}
				}
			}
		}
		
		offset += 288 
	}
	
	
	for i := uint32(5); i < numberOfModules; i++ {
		if offset+288 > uintptr(len(buffer)) {
			break
		}
		
		imageBase := *(*uintptr)(unsafe.Pointer(&buffer[offset+20])) 
		
		for nameStart := uintptr(40); nameStart <= 50; nameStart++ {
			namePtr := offset + nameStart
			if namePtr < uintptr(len(buffer)) && namePtr+100 < uintptr(len(buffer)) {
				nameBytes := buffer[namePtr:]
				var nameEnd int
				for j, b := range nameBytes {
					if b == 0 || j >= 100 {
						nameEnd = j
						break
					}
				}
				
				if nameEnd > 5 {
					name := strings.ToLower(string(nameBytes[:nameEnd]))
					if strings.Contains(name, "\\") || strings.Contains(name, ".") {
						if strings.Contains(name, targetModule) || strings.Contains(name, "ntoskrnl") {
							return imageBase, nil
						}
						break 
					}
				}
			}
		}
		
		offset += 288
	}
	
	return 0, fmt.Errorf("kernel module '%s' not found", moduleName)
}


func GetAllKernelModules() ([]KernelModule, error) {
	bufferSize := uintptr(64 * 1024) 
	buffer := make([]byte, bufferSize)
	
	ret, err := winapi.NtQuerySystemInformation(
		uintptr(SystemModuleInformation),
		unsafe.Pointer(&buffer[0]),
		bufferSize,
		&bufferSize)
	

	if ret == 0xC0000004 { 
		if bufferSize == 0 {
			return nil, fmt.Errorf("returned buffer size is 0")
		}
		
		buffer = make([]byte, bufferSize)
		ret, err = winapi.NtQuerySystemInformation(
			uintptr(SystemModuleInformation),
			unsafe.Pointer(&buffer[0]),
			bufferSize,
			&bufferSize)
	}
	
	if ret != 0 {
		return nil, fmt.Errorf("NtQuerySystemInformation failed, status: 0x%X, err: %v", ret, err)
	}
	
	if len(buffer) < 8 {
		return nil, fmt.Errorf("buffer too small: %d bytes (need at least 8)", len(buffer))
	}
	
	numberOfModules := *(*uintptr)(unsafe.Pointer(&buffer[0]))
	modules := make([]KernelModule, 0, numberOfModules)
	offset := uintptr(8) 
	
	for i := uintptr(0); i < numberOfModules; i++ {
		if offset+280 > uintptr(len(buffer)) {
			break
		}
		
		baseAddr := *(*uintptr)(unsafe.Pointer(&buffer[offset]))
		size := *(*uint32)(unsafe.Pointer(&buffer[offset+8]))
		nameOffset := *(*uint16)(unsafe.Pointer(&buffer[offset+22]))
		namePtr := offset + 24 + uintptr(nameOffset)
		
		var module KernelModule
		module.BaseAddress = baseAddr
		module.Size = size
		
		if namePtr < uintptr(len(buffer)) {
			nameBytes := buffer[namePtr:]
			var nameEnd int
			for j, b := range nameBytes {
				if b == 0 || j >= MAX_MODULE_NAME {
					nameEnd = j
					break
				}
			}
			if nameEnd > 0 && nameEnd < MAX_MODULE_NAME {
				copy(module.Name[:nameEnd], nameBytes[:nameEnd])
			}
		}
		
		modules = append(modules, module)
		offset += 280
	}
	
	return modules, nil
}

func GetModuleName(module *KernelModule) string {
	nameBytes := module.Name[:]
	var nameEnd int
	for j, b := range nameBytes {
		if b == 0 {
			nameEnd = j
			break
		}
	}
	if nameEnd == 0 {
		nameEnd = len(nameBytes)
	}
	return string(nameBytes[:nameEnd])
}
