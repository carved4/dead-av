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


type RTL_PROCESS_MODULE_INFORMATION struct {
	Section         uintptr   // 8 bytes on x64
	MappedBase      uintptr   // 8 bytes on x64 
	ImageBase       uintptr   // 8 bytes on x64 - module base address
	ImageSize       uint32    // 4 bytes
	Flags           uint32    // 4 bytes
	LoadOrderIndex  uint16    // 2 bytes
	InitOrderIndex  uint16    // 2 bytes
	LoadCount       uint16    // 2 bytes
	OffsetToFileName uint16   // 2 bytes - offset to filename within FullPathName
	FullPathName    [256]byte // 256 bytes
}


func parseModuleInfo(buffer []byte, offset uintptr) (uintptr, uint32, string, string) {
	if offset+304 > uintptr(len(buffer)) {
		return 0, 0, "", ""
	}
	

	imageBase := *(*uintptr)(unsafe.Pointer(&buffer[offset+20]))
	imageSize := *(*uint32)(unsafe.Pointer(&buffer[offset+28]))
	nameOffset := *(*uint16)(unsafe.Pointer(&buffer[offset+44]))
	

	pathStart := offset + 48
	if pathStart+256 > uintptr(len(buffer)) {
		return imageBase, imageSize, "", ""
	}
	
	pathBytes := buffer[pathStart : pathStart+256]
	var pathEnd int
	for i, b := range pathBytes {
		if b == 0 {
			pathEnd = i
			break
		}
	}
	
	fullPath := ""
	if pathEnd > 0 {
		fullPath = string(pathBytes[:pathEnd])
	}
	

	name := ""
	if nameOffset < 256 && int(nameOffset) < len(pathBytes) {
		nameBytes := pathBytes[nameOffset:]
		var nameEnd int
		for i, b := range nameBytes {
			if b == 0 {
				nameEnd = i
				break
			}
		}
		if nameEnd > 0 {
			name = string(nameBytes[:nameEnd])
		}
	}
	

	if name == "" && fullPath != "" {
		if lastSlash := strings.LastIndex(fullPath, "\\"); lastSlash != -1 {
			name = fullPath[lastSlash+1:]
		} else {
			name = fullPath
		}
	}
	
	return imageBase, imageSize, name, fullPath
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
	
	if ret == 0xC0000004 { // STATUS_INFO_LENGTH_MISMATCH
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
	
	if len(buffer) < int(unsafe.Sizeof(uint32(0))) {
		return 0, fmt.Errorf("buffer too small: %d bytes", len(buffer))
	}
	
	numberOfModules := *(*uint32)(unsafe.Pointer(&buffer[0]))
	offset := uintptr(unsafe.Sizeof(uint32(0))) // Skip the ULONG count
	structSize := unsafe.Sizeof(RTL_PROCESS_MODULE_INFORMATION{})
	targetModule := strings.ToLower(moduleName)
	
	fmt.Printf("[+] Scanning %d kernel modules for '%s'...\n", numberOfModules, moduleName)
	
	for i := uint32(0); i < numberOfModules; i++ {
		if offset+structSize > uintptr(len(buffer)) {
			break
		}
		
		imageBase, _, moduleFileName, _ := parseModuleInfo(buffer, offset)
		
		if moduleFileName != "" {
			moduleNameLower := strings.ToLower(moduleFileName)
			
			// Check if this is the target module
			if strings.Contains(moduleNameLower, targetModule) || 
			   (targetModule == "ntoskrnl.exe" && strings.Contains(moduleNameLower, "ntoskrnl")) {
				return imageBase, nil
			}
		}
		
		offset += structSize
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

	if ret == 0xC0000004 { // STATUS_INFO_LENGTH_MISMATCH
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
	
	if len(buffer) < int(unsafe.Sizeof(uint32(0))) {
		return nil, fmt.Errorf("buffer too small: %d bytes", len(buffer))
	}
	
	numberOfModules := *(*uint32)(unsafe.Pointer(&buffer[0]))
	modules := make([]KernelModule, 0, numberOfModules)
	offset := uintptr(unsafe.Sizeof(uint32(0))) // Skip the ULONG count
	structSize := unsafe.Sizeof(RTL_PROCESS_MODULE_INFORMATION{})
	
	for i := uint32(0); i < numberOfModules; i++ {
		if offset+structSize > uintptr(len(buffer)) {
			break
		}
		
		imageBase, imageSize, moduleName, _ := parseModuleInfo(buffer, offset)
		
		var module KernelModule
		module.BaseAddress = imageBase
		module.Size = imageSize
		

		if moduleName != "" && len(moduleName) < MAX_MODULE_NAME {
			copy(module.Name[:len(moduleName)], []byte(moduleName))
		}
		
		modules = append(modules, module)
		offset += structSize
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
