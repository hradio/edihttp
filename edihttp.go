// edihttp
package main

import (
	"crypto/rand"
	"edisplitter"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"

	"strconv"
	"strings"
	"time"
)

type EdiFrame struct {
	SubchannelId uint8
	EdiData      []byte
}

var ipAddresses []net.IP
var hostAddress []string

//SBT_SUBCHANS
var mSbtConfig = make(map[uint8]int)

type toggleSlideMapIdx struct {
	toggleStartTime		int64
	toggleBuffPos		int64
}
//map from SubchanId to map from BuffTogglePoint to DLabel
var (
	mTogglesMap map[uint8]map[int64]edisplitter.DynamicLabel = make(map[uint8]map[int64]edisplitter.DynamicLabel)
	//map subchanId to toggle start time
	mTogglesSlideMap = make(map[uint8][]toggleSlideMapIdx)
	mToggleMapMutex = sync.RWMutex{}
)

func cmdFlagProvided(cmdName string) (provided bool) {
	flag.Visit(func(f *flag.Flag) {
		if f.Name == cmdName {
			provided = true
		}
	})
	return
}

var mListOnlyCmd = false

//Configuration file
type Configuration struct {
	AfVersion		int			`json:"afVersion"`
	ConfigVersion	float32		`json:"configVersion"`
	Hosts			string		`json:"hosts"`
	HttpPort		int			`json:"httpPort"`
	MaxGlobalSbt	int			`json:"maxGlobalSbt"`
	ProxyPort		int			`json:"proxyPort"`
	SbtChans		string		`json:"sbtChans"`
	UdpPort			int			`json:"udpPort"`
	Verbose			bool		`json:"verbose"`
}

var mConfiguration *Configuration = nil

func loadConfiguration(config string) {
	mConfiguration = new(Configuration)

	configFile, err := os.Open(config)
	defer configFile.Close()

	if err == nil {
		confParser := json.NewDecoder(configFile)
		err = confParser.Decode(mConfiguration)
		if err != nil {
			fmt.Printf("%s : Error decoding config file: %s - %s\n", time.Now().Format(time.UnixDate), config, err.Error())
		}
	}
}

const EDIHTTP_CONF_FILENAME string 		= "edihttp.conf"

//Docker environment variables
const ENV_EDIHTTP_CONFIGPATH string 	= "EDIHTTP_CONFIGPATH"
const ENV_EDIHTTP_MAX_GLOB_SBT string 	= "EDIHTTP_MAX_TIMESHIFT_GLOBAL"
const ENV_EDIHTTP_SBT_SUBCHANS string 	= "EDIHTTP_SBT_SUBCHANS"
const ENV_EDIHTTP_VERBOSE string 		= "EDIHTTP_VERBOSE"
const ENV_EDIHTTP_UDP_PORT string 		= "EDIHTTP_UDP_PORT"
const ENV_EDIHTTP_HTTP_PORT string 		= "EDIHTTP_HTTP_PORT"
const ENV_EDIHTTP_PROXY_PORT string 	= "EDIHTTP_PROXY_PORT"
const ENV_EDIHTTP_HOSTS string 			= "EDIHTTP_HOSTS"

//Command line parameters
const CMD_EDIHTTP_CONFIGPATH string 	= "configPath"
const CMD_EDIHTTP_MAXSBT string 		= "maxsbt"
const CMD_EDIHTTP_SBTCHANS string 		= "sbtchans"
const CMD_EDIHTTP_AFVERSION string 		= "afversion"
const CMD_EDIHTTP_HOSTS string 			= "hosts"
const CMD_EDIHTTP_UDPPORT string 		= "udpport"
const CMD_EDIHTTP_HTTPPORT string 		= "httpport"
const CMD_EDIHTTP_PROXYPORT string 		= "proxyport"
const CMD_EDIHTTP_LISTSUBCHANS string 	= "listsubchans"
const CMD_EDIHTTP_VERBOSE string 		= "verbose"

func main() {
	var err error
	var cmdConfigPath string
	var sbtchans string
	var outHttpPort int
	var verbose = false
	var overrideProxyPort int
	var inUdpPort int
	var configPath string

	cmdMaxSbt := flag.Int(CMD_EDIHTTP_MAXSBT, 60, "the available global sbt buffer for all timeshiftable subchannels in minutes, the minimum is 5.")
	flag.StringVar(&sbtchans, CMD_EDIHTTP_SBTCHANS, "", "comma separated list of subchannel-ids that are available for timeshifting.\n\te.g. --sbtchans=2,12,16 or --sbtchans=0x02,0x0C,0x10.\n" +
		"Use --sbtchans=all to enable timeshifting for all subchannels.\n" +
		"To set the maximum sbt buffer for a specific subchannel use\n\t--sbtchans=2:10,12:60,16:120 to have a buffer for subchannel 2 of 10 minutes, for subchannel 12 of 60 minutes...\n" +
		"This overrides the 'maxsbt' parameter for the specific subchannel")
	afVersion := flag.Int(CMD_EDIHTTP_AFVERSION, 1, "set the AF version to use. Experimental feature to reduce EDI overhead.")

	ipOverrideString := flag.String(CMD_EDIHTTP_HOSTS, "", "comma separated list of IP addresses to display on web overview page")
	flag.IntVar(&inUdpPort, CMD_EDIHTTP_UDPPORT, 50000, "Set the incoming EDI UDP port")
	flag.IntVar(&outHttpPort, CMD_EDIHTTP_HTTPPORT, 8187, "Set the port of the HTTP streams and overview page")
	flag.IntVar(&overrideProxyPort, CMD_EDIHTTP_PROXYPORT, 0, "Set the port where to receive streams on. Only useful if a (reverse) proxy is used.")

	flag.BoolVar(&mListOnlyCmd, CMD_EDIHTTP_LISTSUBCHANS, false, "Lists all available subchannels and exits")
	flag.BoolVar(&verbose, CMD_EDIHTTP_VERBOSE, false, "Enables debug output on stdout")

	flag.StringVar(&cmdConfigPath, CMD_EDIHTTP_CONFIGPATH,"./", "Set the path to 'edihttp.conf' file, e.g. /etc/ediconf/")

	flag.Parse()

	if envConfigPath := os.Getenv(ENV_EDIHTTP_CONFIGPATH); len(envConfigPath) > 0 {
		fmt.Printf("%s : Config ENV configPath: %s\n", time.Now().String(), envConfigPath)
		configPath = envConfigPath
	}

	if cmdFlagProvided(CMD_EDIHTTP_CONFIGPATH) || len(configPath) == 0{
		fmt.Printf("%s : Config CMD configPath: %s\n", time.Now().Format(time.UnixDate), cmdConfigPath)
		configPath = cmdConfigPath
	}

	if !strings.HasSuffix(configPath, "/") {
		configPath = configPath + "/"
		fmt.Printf("%s : Loading config from appended: %s\n", time.Now().Format(time.UnixDate), configPath)
	}

	configPath += EDIHTTP_CONF_FILENAME

	fmt.Printf("%s : Loading config from: %s\n", time.Now().Format(time.UnixDate), configPath)
	loadConfiguration(configPath)

	//Gloabel SBT buffer config
	if envMaxGlobalTimeshift, err := strconv.Atoi(os.Getenv(ENV_EDIHTTP_MAX_GLOB_SBT)); err == nil {
		mConfiguration.MaxGlobalSbt = envMaxGlobalTimeshift
	}

	if cmdFlagProvided(CMD_EDIHTTP_MAXSBT ) {
		mConfiguration.MaxGlobalSbt = *cmdMaxSbt
	}

	if mConfiguration.MaxGlobalSbt == 0 {
		mConfiguration.MaxGlobalSbt = *cmdMaxSbt
	}

	//Subchans config
	if envSbtchans := os.Getenv(ENV_EDIHTTP_SBT_SUBCHANS); len(envSbtchans) > 0 {
		mConfiguration.SbtChans = envSbtchans
		fmt.Printf("%s : Config ENV sbtchans: %s\n", time.Now().Format(time.UnixDate), envSbtchans)
	}

	if cmdFlagProvided(CMD_EDIHTTP_SBTCHANS) || len(mConfiguration.SbtChans) == 0 {
		fmt.Printf("%s : Config CMD sbtchans: %s\n", time.Now().Format(time.UnixDate), sbtchans)
		mConfiguration.SbtChans = sbtchans
	}

	//Verbosity config
	if envVerboseStr := os.Getenv(ENV_EDIHTTP_VERBOSE); len(envVerboseStr) > 0 {
		envVerbose, err := strconv.ParseBool(envVerboseStr)
		if err == nil {
			mConfiguration.Verbose = envVerbose
		}
	}

	if cmdFlagProvided(CMD_EDIHTTP_VERBOSE) {
		mConfiguration.Verbose = verbose
	}

	edisplitter.SetVerbosity(mConfiguration.Verbose)
	edisplitter.SetAfVersion(*afVersion)

	if envUdpPort, err := strconv.Atoi(os.Getenv(ENV_EDIHTTP_UDP_PORT)); err == nil {
		mConfiguration.UdpPort = envUdpPort
	}

	if cmdFlagProvided(CMD_EDIHTTP_UDPPORT) {
		mConfiguration.UdpPort = inUdpPort
	}

	if mConfiguration.UdpPort == 0 {
		mConfiguration.UdpPort = inUdpPort
	}

	if envHttpPort, err := strconv.Atoi(os.Getenv(ENV_EDIHTTP_HTTP_PORT)); err == nil {
		mConfiguration.HttpPort = envHttpPort
	}

	if cmdFlagProvided(CMD_EDIHTTP_HTTPPORT) {
		mConfiguration.HttpPort = outHttpPort
	}

	if mConfiguration.HttpPort == 0 {
		mConfiguration.HttpPort = outHttpPort
	}

	if envProxyPort, err := strconv.Atoi(os.Getenv(ENV_EDIHTTP_PROXY_PORT)); err == nil {
		fmt.Printf("%s : Config ENV proxyport: %d\n", time.Now().Format(time.UnixDate), envProxyPort)
		mConfiguration.ProxyPort = envProxyPort
	}

	if cmdFlagProvided(CMD_EDIHTTP_PROXYPORT) {
		fmt.Printf("%s : Config CMD proxyport: %d\n", time.Now().Format(time.UnixDate), overrideProxyPort)
		mConfiguration.ProxyPort = overrideProxyPort
	}

	if mConfiguration.ProxyPort == 0 {
		fmt.Printf("%s : Config proxyport not given, setting it to HTTPport\n", time.Now().Format(time.UnixDate))
		mConfiguration.ProxyPort = mConfiguration.HttpPort
	}

	if envSbtChans := os.Getenv(ENV_EDIHTTP_SBT_SUBCHANS); len(envSbtChans) > 0 {
		mConfiguration.SbtChans = envSbtChans
	}

	if cmdFlagProvided(CMD_EDIHTTP_SBTCHANS) || len(mConfiguration.SbtChans) == 0 {
		mConfiguration.SbtChans = sbtchans
	}

	if envHosts := os.Getenv(ENV_EDIHTTP_HOSTS); len(envHosts) > 0 {
		mConfiguration.Hosts = envHosts
		fmt.Printf("%s : Config ENV hosts: %s\n", time.Now().Format(time.UnixDate), envHosts)
	}

	if cmdFlagProvided(CMD_EDIHTTP_HOSTS) || len(mConfiguration.Hosts) == 0 {
		mConfiguration.Hosts = *ipOverrideString
		fmt.Printf("%s : Config CMD hosts: %s\n", time.Now().Format(time.UnixDate), *ipOverrideString)
	}

	hostAddress = strings.Split(mConfiguration.Hosts, ",")

	if len(mConfiguration.SbtChans) > 0 {
		if mConfiguration.SbtChans == "all" {
			if mConfiguration.Verbose { fmt.Printf("%s : SBT adding all possible Subchannels enabled\n", time.Now().Format(time.UnixDate)) }
			for subId := uint8(0); subId <= 0x3F; subId++ {
				mSbtConfig[subId] = mConfiguration.MaxGlobalSbt
			}
		} else {
			sbtChansSplit := strings.Split(mConfiguration.SbtChans, ",")
			for _, sbtChan := range sbtChansSplit {

				sbtSubMax := strings.Split(sbtChan, ":")

				if len(sbtSubMax) > 0 {
					var subchanId uint64
					var parseErr error
					var subMaxSbt = mConfiguration.MaxGlobalSbt

					if strings.HasPrefix(sbtSubMax[0], "0x") {
						subchanId, parseErr = strconv.ParseUint(strings.TrimPrefix(sbtSubMax[0], "0x"), 16, 8)
					} else {
						subchanId, parseErr = strconv.ParseUint(sbtSubMax[0], 10, 8)
					}

					if mConfiguration.Verbose { fmt.Printf("%s : SBT Chan: 0x%02X\n", time.Now().Format(time.UnixDate), subchanId) }
					if parseErr != nil {
						if mConfiguration.Verbose { fmt.Printf("%s : SBT Error handling sbtchans cmd parameter: %s\n", time.Now().Format(time.UnixDate), sbtSubMax[0]) }
						os.Exit(1)
					}

					if len(sbtSubMax) == 2 {
						subMaxSbt, parseErr = strconv.Atoi(sbtSubMax[1])
						if parseErr != nil {
							if mConfiguration.Verbose { fmt.Printf("%s : SBT Error handling sbtchans cmd parameter: %s\n", time.Now().Format(time.UnixDate), sbtSubMax[0]) }
							os.Exit(1)
						}

						if mConfiguration.Verbose { fmt.Printf("%s : SBT MaxSbt: %d\n", time.Now().Format(time.UnixDate), subMaxSbt) }
					}

					if mConfiguration.Verbose { fmt.Printf("%s : SBT: Subchannel 0x%02X mAxSbt: %d\n", time.Now().Format(time.UnixDate), subchanId, subMaxSbt) }
					mSbtConfig[uint8(subchanId)] = subMaxSbt
				}
			}
		}
	}

	if mConfiguration.Verbose { fmt.Printf("%s : USE_HTTPS: %s\n", time.Now().Format(time.UnixDate), os.Getenv("USE_HTTPS")) }
	useSslInt, err := strconv.Atoi(os.Getenv("USE_HTTPS"))
	if err != nil {
		useSslInt = 0
	}

	if mConfiguration.Verbose { fmt.Printf("%s : OVERRIDE_PROXY_PORT: %d - %s\n", time.Now().Format(time.UnixDate), mConfiguration.ProxyPort, os.Getenv("OVERRIDE_PROXY_PORT")) }

	ifaces, err := net.Interfaces()
	if err == nil {
		for _, i := range ifaces {
			addrs, err := i.Addrs()
			if mConfiguration.Verbose { fmt.Printf("%s : IPIfaceName: %s\n", time.Now().Format(time.UnixDate), i.Name) }
			if err == nil {
				for _, addr := range addrs {
					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ip = v.IP
						if ip.To4() != nil {
							if mConfiguration.Verbose { fmt.Printf("%s : IPNetAddress: %s\n", time.Now().Format(time.UnixDate), ip) }

							ipAddresses = append(ipAddresses, ip)
						}
					case *net.IPAddr:
						ip = v.IP
						if mConfiguration.Verbose { fmt.Printf("%s : IPAddress: %s\n", time.Now().Format(time.UnixDate), ip) }
					}
					// process IP address
				}
			}
		}
	} else {
		if mConfiguration.Verbose { fmt.Println("ErrorOccured getting interfaces") }
	}

	useSsl := false
	if useSslInt == 1 {
		useSsl = true
	}

	outHttpPortS := ":" + strconv.Itoa(mConfiguration.HttpPort)
	if mConfiguration.Verbose { fmt.Printf("%s : ENV: %d - %s\n", time.Now().Format(time.UnixDate), mConfiguration.UdpPort, outHttpPortS) }

	go listenServer(mConfiguration.UdpPort, outHttpPortS, useSsl)
	select {}
}

var mDabServiceNew []*edisplitter.DabSrv = nil

func listenServer(udpInPort int, outHttpPort string, usessl bool) {
	if mConfiguration.Verbose { fmt.Printf("%s : Starting to listen\n", time.Now().Format(time.UnixDate)) }

	addr := net.UDPAddr{
		Port: udpInPort,
		IP:   net.ParseIP("0.0.0.0"),
	}

	con, err := net.ListenUDP("udp", &addr)
	if err != nil {
		if mConfiguration.Verbose { fmt.Printf("%s : Error listening on UDP socket %v\n", time.Now().Format(time.UnixDate), err) }
		return
	}

	ediSplitterChan := make(chan []byte, 10000)
	go edisplitter.ParseEdiData(ediSplitterChan)

	var mDoneCbNew func (dabServices []*edisplitter.DabSrv)
	mDoneCbNew = func (dabServices []*edisplitter.DabSrv) {
		if mConfiguration.Verbose { fmt.Printf("%s : DONECBNew: %d\n", time.Now().Format(time.UnixDate), len(dabServices)) }

		edisplitter.UnregisterServicesReadyCallbackNew(mDoneCbNew)
		mDabServiceNew = dabServices

		//For debugging purpose FullEdi
		fullSrv := new(edisplitter.DabSrv)
		fullSrv.ServiceId = 0xFFFF
		fullSrv.ServiceLabel = "FullEDI"
		fullSrv.ServiceShortLabel = "FEDI"
		fullSrv.NumSrvComponents = 1
		fullSrv.CAId = 0
		fullSrv.IsProgramme = true
		fullSrv.AfFrameOutput = make(chan []byte, 10)

		fullComp := new(edisplitter.DabSrvComponent)
		fullComp.IsPrimary = true
		fullComp.SCIDs = 0xFF
		fullComp.ASCTy = 63
		fullComp.ServiceId = 0xFFFF
		fullComp.SubChannelId = 0xFF

		fullSubchan := new(edisplitter.DabSrvSubchannel)
		fullComp.Subchannel = fullSubchan

		fullSrv.DabServiceComponents = append(fullSrv.DabServiceComponents, fullComp)
		mDabServiceNew = append(mDabServiceNew, fullSrv)
		//FullEdi

		if mListOnlyCmd {
			fmt.Printf("------------------------------\n")
			fmt.Printf("-- %d DabServices available --\n", len(dabServices))
			fmt.Printf("------------------------------\n")
			for _, dabSrv := range dabServices {
				fmt.Printf("-- Label: %16s  --\n-- isProgramme: %5t       --\n", dabSrv.ServiceLabel, dabSrv.IsProgramme)
				for _, srvComp := range dabSrv.DabServiceComponents {
					if srvComp.IsPrimary {
						fmt.Printf("-- SubchannelId: 0x%02X - %2d  --\n", srvComp.Subchannel.SubchannelId, srvComp.Subchannel.SubchannelId)
						break
					}
				}
				fmt.Printf("------------------------------\n")
			}
			os.Exit(0)
		}

		if !usessl {
			if mConfiguration.Verbose { fmt.Printf("%s : Starting unsecure WebserverNew: %s\n", time.Now().Format(time.UnixDate), outHttpPort) }
			go startWebserverNew(mDabServiceNew, outHttpPort)
		} else {
			if mConfiguration.Verbose { fmt.Printf("%s : Starting secure WebserverNew: %s\n", time.Now().Format(time.UnixDate), outHttpPort) }
			go startSecureWebserverNew(mDabServiceNew, outHttpPort)
		}
	}
	edisplitter.RegisterServicesReadyCallbackNew(mDoneCbNew)

	mToggleCallback := func(dLabel edisplitter.DynamicLabel) {
		mToggleMapMutex.Lock()
		if  _, exists := mTogglesMap[dLabel.SubchanId]; !exists {
			if mConfiguration.Verbose { fmt.Printf("%s : ToggleC adding map for SubchanId: 0x%02X\n", time.Now().Format(time.UnixDate), dLabel.SubchanId) }
			mTogglesMap[dLabel.SubchanId] = make(map[int64]edisplitter.DynamicLabel)
		}
		mToggleMapMutex.Unlock()

		//map AF-Sequencenumber to Bufferposition
		if sbtBuffer, exists := sbtBuffers[dLabel.SubchanId]; exists {
			if sbtBuffer.isTimeshiftable {
				var toggleBufPos int64 = (int64(dLabel.AfSeqNum) + (int64(dLabel.AfMulti) * 65535)) - int64(sbtBuffer.zeroAfNum)
				if toggleBufPos >= 0 {
					dLabel.ToggleId = toggleBufPos

					if mConfiguration.Verbose {
						fmt.Printf("%s : ToggleC_0x%02X BufferAfZero: %d, ToggleAf: %d, AfMultiVal: %d, ToggleBuf: %d, %s\n", time.Now().Format(time.UnixDate), dLabel.SubchanId, int64(sbtBuffer.zeroAfNum), int64(dLabel.AfSeqNum), uint64(dLabel.AfMulti)*65535, toggleBufPos, dLabel.FullLabel)
					}

					edisplitter.MPendingToggleMutex.Lock()
					edisplitter.MPendingToggle[dLabel.SubchanId] = &dLabel
					edisplitter.MPendingToggleMutex.Unlock()
					mToggleMapMutex.Lock()
					mTogglesMap[dLabel.SubchanId][toggleBufPos] = dLabel
					mTogglesSlideMap[dLabel.SubchanId] = append(mTogglesSlideMap[dLabel.SubchanId], toggleSlideMapIdx{
						toggleStartTime: dLabel.ReceiveTime,
						toggleBuffPos:   toggleBufPos,
					})
					mToggleMapMutex.Unlock()
				} else {
					if mConfiguration.Verbose { fmt.Printf("%s : Invalid ToggleBuffPos 0x%02X BufferAfZero: %d, ToggleAf: %d, AfMultiVal: %d, ToggleBuf: %d\n", time.Now().Format(time.UnixDate), dLabel.SubchanId, int64(sbtBuffer.zeroAfNum), int64(dLabel.AfSeqNum), uint64(dLabel.AfMulti)*65535, toggleBufPos) }
				}
			}
		}
	}
	edisplitter.RegisterToggleCallback(mToggleCallback)

	mSlideshowCallback := func(slide edisplitter.MotSlideshow) {

		toggleSlidePath :=  fmt.Sprintf("toggleslides/%d/", slide.SubchannelId)
		if _, err := os.Stat(toggleSlidePath); os.IsNotExist(err) {
			if mConfiguration.Verbose { fmt.Printf("%s : SLSCB for SubchanId: 0x%02X, creating dir at %s\n", time.Now().Format(time.UnixDate), slide.SubchannelId, toggleSlidePath) }
			_ = os.MkdirAll(toggleSlidePath, os.ModePerm)
		}

		mToggleMapMutex.Lock()
		if _, exists := mTogglesSlideMap[slide.SubchannelId]; exists {
			lenList := len(mTogglesSlideMap[slide.SubchannelId])
			toggleDiff := int64(-31000)
			var toggle edisplitter.DynamicLabel
			toggleBuffPos := int64(0)
			if lenList > 0 {
				lastToggleTime := mTogglesSlideMap[slide.SubchannelId][lenList-1].toggleStartTime
				toggleDiff = lastToggleTime - slide.ReceiveTime.UnixNano()/1000000
				toggleBuffPos = mTogglesSlideMap[slide.SubchannelId][lenList-1].toggleBuffPos
				toggle = mTogglesMap[slide.SubchannelId][toggleBuffPos]
			}

			if toggleDiff >= -30000 {
				if mConfiguration.Verbose { fmt.Printf("%s : SLSCB_0x%02X saving toggle: %s : %d TimeDiff: %d : %s - %d\n", time.Now().Format(time.UnixDate), slide.SubchannelId, toggle.FullLabel, toggle.ReceiveTime, toggleDiff, slide.ContentName, mTogglesSlideMap[slide.SubchannelId][lenList-1].toggleBuffPos) }
				writeErr := ioutil.WriteFile(fmt.Sprintf("%s%d", toggleSlidePath, mTogglesSlideMap[slide.SubchannelId][lenList-1].toggleBuffPos), slide.ImageData, 0644)
				if writeErr != nil {
					if mConfiguration.Verbose { fmt.Printf("%s : SLSCB write failed: %s\n", time.Now().Format(time.UnixDate), writeErr) }
				}

				togCopy := toggle
				togCopy.SlideMime = slide.ContentMime
				togCopy.SlidePath = "/" + toggleSlidePath + strconv.Itoa(int(toggleBuffPos))
				mTogglesMap[slide.SubchannelId][toggleBuffPos] = togCopy

				if mConfiguration.Verbose { fmt.Printf("%s : Adding LiveToggle again for SLS update for Subchan: 0x%02X - %d - %s\n", time.Now().Format(time.UnixDate), slide.SubchannelId, togCopy.ToggleId, time.Now())}
				edisplitter.MPendingToggleMutex.Lock()
				edisplitter.MPendingToggle[slide.SubchannelId] = &togCopy
				edisplitter.MPendingToggleMutex.Unlock()

				if mConfiguration.Verbose { fmt.Printf("%s : SLSCB_0x%02X Saved Toggle: %s - %s\n", time.Now().Format(time.UnixDate), slide.SubchannelId, mTogglesMap[slide.SubchannelId][toggleBuffPos].SlideMime, mTogglesMap[slide.SubchannelId][toggleBuffPos].SlidePath) }
			}
		}
		mToggleMapMutex.Unlock()
	}
	edisplitter.RegisterSlideshowCallback(mSlideshowCallback)

	udpBuff := make([]byte, 3900)

	for {
		read, _, err := con.ReadFromUDP(udpBuff)
		if err != nil {
			fmt.Println("Error reading from UDP socket")
			return
		}

		ediData := make([]byte, read)
		copy(ediData, udpBuff[:read])

		//For debugging purpose FullEdi
		if mDabServiceNew != nil {
			for _, srv := range mDabServiceNew {
				if srv.ServiceId == 0xFFFF {
					//fmt.Printf("FullEdi sending data\n")
					srv.AfFrameOutput <- ediData
					break
				}
			}
		}
		//FullEdi

		ediSplitterChan <- ediData
	}
}

type SbtClient struct {
	clientToken 	string
	readAfs 		uint64
	ediDataChan 	[]chan []byte
	bufferBurst 	bool
	burstChan		*chan []byte
	paused 			bool
	pauseHb			int64
}

type StreamingServer struct {
	HttpServer http.Server

	// EdiFrames are pushed to this channel by the main dabservice routine
	EdiData chan *EdiFrame

	// New client connections
	newClients chan func() (uint8, string, uint64, chan []byte)

	// Closed client connections
	closingClients chan func() (uint8, chan []byte)

	// Client connections registry
	clients map[uint8][]chan []byte

	sbtClients map[uint8][]*SbtClient
}

func startWebserverNew(srvs []*edisplitter.DabSrv, httpPort string) {
	fmt.Printf("%s : Starting server\n", time.Now().Format(time.UnixDate))
	streamingServer := NewServer()

	for _, dabSrv := range srvs {
		if mConfiguration.Verbose { fmt.Printf("%s : Starting HandleStreamGo for: 0x%08X\n", time.Now().Format(time.UnixDate), dabSrv.ServiceId) }
		go handleStreamGoNew(streamingServer, dabSrv)
	}

	fmt.Printf("%s : Starting to listen on HTTP port %s\n", time.Now().Format(time.UnixDate), httpPort)
	err := http.ListenAndServe(httpPort, streamingServer)

	if err != nil {
		fmt.Printf("%s : Error occured at starting Webserver: %s\n", time.Now().Format(time.UnixDate), err)
	}
}

func startSecureWebserverNew(srvs []*edisplitter.DabSrv, httpPort string) {
	fmt.Println("Starting Secure Webserver")
	streamingServer := NewServer()

	for _, dabSrv := range srvs {
		if mConfiguration.Verbose { fmt.Printf("Starting HandleStreamGo for: 0x%08X\n", dabSrv.ServiceId) }
		go handleStreamGoNew(streamingServer, dabSrv)
	}

	fmt.Println("Starting to listen on https")
	tlsErr := http.ListenAndServeTLS(":8188", "/etc/letsencrypt/live/edistream.irt.de/fullchain.pem", "/etc/letsencrypt/live/edistream.irt.de/privkey.pem", streamingServer)
	if tlsErr != nil {
		if mConfiguration.Verbose { fmt.Printf("Error listening for https requests: %s\n", tlsErr) }
	}
}

func NewServer() (server *StreamingServer) {
	// Instantiate
	server = &StreamingServer{
		HttpServer:    http.Server{
			ReadTimeout:       5 * time.Second,
			WriteTimeout:      2 * time.Second,

		},
		newClients:     make(chan func() (uint8, string, uint64, chan []byte)),
		closingClients: make(chan func() (uint8, chan []byte)),
		EdiData:        make(chan *EdiFrame, 1000), //addedBuffer for client-load testing
		sbtClients:		make(map[uint8][]*SbtClient),

	}

	// Set it running - listening and broadcasting events
	go server.listen()

	return
}

// Listen on different channels and act accordingly
func (server *StreamingServer) listen() {
	for {
		select {
		case s := <-server.closingClients:
			sub, dataChan := s()

			for _, delClient := range server.sbtClients[sub] {
				for chanIdx, delChan := range delClient.ediDataChan {
					if delChan == dataChan {
						delClient.ediDataChan = append(delClient.ediDataChan[:chanIdx], delClient.ediDataChan[chanIdx+1:]...)
						fmt.Printf("%s : Found channel to delete with TimeshiftToken: %s, %d clients remaining\n", time.Now().Format(time.UnixDate), delClient.clientToken, len(delClient.ediDataChan))
					}
				}
			}

		case s := <-server.newClients:
			sub, clientToken, readAfs, subChan := s()
			newSbtClient := new(SbtClient)
			newSbtClient.ediDataChan = append(newSbtClient.ediDataChan, subChan)
			newSbtClient.clientToken = clientToken
			newSbtClient.readAfs = readAfs
			/*newSbtClient.bufferBurst = true
			newSbtClient.burstChan = &subChan
			newSbtClient.paused = false
			server.sbtClients[sub] = append(server.sbtClients[sub], newSbtClient)
			*/
			if mConfiguration.Verbose { fmt.Printf("%s : SBT Added Client %d for Subchan: %d with CLientToken: %s\n", time.Now().Format(time.UnixDate), len(server.clients[sub]), sub, clientToken) }
			FindDabSrv:
			for _, dabSrv := range mDabServiceNew {
				for _, srvComp := range dabSrv.DabServiceComponents {
					if srvComp.SubChannelId == sub {
						if mConfiguration.Verbose { fmt.Printf("%s : SBT Added Client sending DETIAF\n", time.Now().Format(time.UnixDate)) }
						//TODO FullEdi
						if srvComp.SubChannelId != 0xFF {
							for detiCnt := 0; detiCnt < 4; detiCnt++ {
								subChan <- edisplitter.CreateDetiAF(dabSrv)
							}
						}
						//TODO FullEdi
						break FindDabSrv
					}
				}
			}
			newSbtClient.bufferBurst = true
			newSbtClient.burstChan = &subChan
			newSbtClient.paused = false
			server.sbtClients[sub] = append(server.sbtClients[sub], newSbtClient)
		}
	}
}

//POST request json structure for controlling timeshiftclient. Mapping from timeshiftToken (lowercase) to public TimeshiftToken
type SbtPostRequest struct {
	TimeshiftToken 	string 	`json:"timeshiftToken"`
	Action 			string 	`json:"action"`
	WantedPos 		int64 	`json:"wantedPos"`
	WantedUts 		int64 	`json:"wantedUts"`
	ToggleId		int64	`json:"toggleId"`
}

func (sbtPost *SbtPostRequest) UnmarshalJSON(b []byte) error {
	type xSbtPostRequest SbtPostRequest
	xSbtPost := &xSbtPostRequest{WantedUts:-1, ToggleId:-1}
	if err := json.Unmarshal(b, xSbtPost); err != nil {
		return err
	}

	*sbtPost = SbtPostRequest(*xSbtPost)
	return nil
}

func (server *StreamingServer) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	//TODO burst buffer request with seconds of buffer

	if req.Method == http.MethodOptions {
		if mConfiguration.Verbose { fmt.Printf("%s : HTTP_OPTIONS %s\n", time.Now().Format(time.UnixDate), req) }

		subchanIdString := strings.TrimPrefix(req.URL.Path, "/services/")
		if mConfiguration.Verbose { fmt.Printf("%s : SBT ClientToken string: %s\n", time.Now().Format(time.UnixDate), subchanIdString) }
		subchanId, err := strconv.Atoi(subchanIdString)

		sbtBuffersMutex.RLock()
		if err != nil && sbtBuffers[uint8(subchanId)].isTimeshiftable {
			rw.Header().Set("Access-Control-Allow-Methods", "POST")
		}
		sbtBuffersMutex.RUnlock()
		rw.Header().Set("Access-Control-Allow-Origin", "*")
		rw.Header().Set("Access-Control-Allow-Headers", "content-type")

		written, err := rw.Write(nil)
		if err != nil {
			if mConfiguration.Verbose { fmt.Printf("%s : Error Writing OPTIONS: %d\n", time.Now().Format(time.UnixDate), written) }
			http.Error(rw, "", http.StatusBadRequest)
		}
	}

	//POST control method incoming
	if req.Method == http.MethodPost {
		if mConfiguration.Verbose { fmt.Printf("%s : HTTP_POST method: %s \n %s\n", time.Now().Format(time.UnixDate), req.URL, req.Body) }

		var postReqJson SbtPostRequest
		err := json.NewDecoder(req.Body).Decode(&postReqJson)
		if err != nil {
			if mConfiguration.Verbose { fmt.Printf("%s : JsonDecoded failed: %s\n", time.Now().Format(time.UnixDate), err.Error()) }
			http.Error(rw, "", http.StatusBadRequest)
			return
		}

		if mConfiguration.Verbose { fmt.Printf("%s : JsonDecoded: Token: %s, WantedPos: %d\n", time.Now().Format(time.UnixDate), postReqJson.TimeshiftToken, postReqJson.WantedPos) }

		reqClientToken := postReqJson.TimeshiftToken
		wantedPosMs := postReqJson.WantedPos
		wantedUts := postReqJson.WantedUts
		toggleId := postReqJson.ToggleId

		fmt.Printf("%s : SeekPTS: WantedUTS: %d, ToggleId: %d\n", time.Now().Format(time.UnixDate),wantedUts, toggleId)

		action := postReqJson.Action
		if mConfiguration.Verbose { fmt.Printf("%s : SBT HTTP POST action: %s clientToken: %s, WantedPos: %d\n", time.Now().Format(time.UnixDate), action, reqClientToken, wantedPosMs) }

		id := strings.TrimPrefix(req.URL.Path, "/services/")
		if mConfiguration.Verbose { fmt.Printf("%s : SBT ClientToken string: %s\n", time.Now().Format(time.UnixDate), id) }
		subchanIdInt, err := strconv.Atoi(id)
		subchanId := uint8(subchanIdInt)

		if err == nil {

			if action == "items" {
				if mConfiguration.Verbose { fmt.Printf("%s : ToggleC for 0x%02X: %d\n", time.Now().Format(time.UnixDate), subchanId, len(mTogglesMap[subchanId])) }
				var togglesJson = []byte("[")

				mToggleMapMutex.Lock()
				for _, toggleItem := range mTogglesMap[subchanId] {
					if mConfiguration.Verbose { fmt.Printf("%s : ToggleC Marshaling: %s\n", time.Now().Format(time.UnixDate), toggleItem.FullLabel) }
					togJson, marshErr := json.Marshal(toggleItem)
					if marshErr == nil {
						togglesJson = append(togglesJson, togJson...)
						togglesJson = append(togglesJson, []byte(",")...)
					}
				}
				mToggleMapMutex.Unlock()
				if len(togglesJson) > 2 {
					togglesJson = togglesJson[:len(togglesJson)-1]
				}

				togglesJson = append(togglesJson, []byte("]")...)

				if mConfiguration.Verbose { fmt.Printf("%s : ToggleCMarshal: %s\n", time.Now().Format(time.UnixDate), togglesJson) }

				rw.Header().Set("Cache-Control", "no-cache")
				rw.Header().Set("Connection", "close")
				rw.Header().Set("Access-Control-Allow-Origin", "*")
				_, _ = rw.Write(togglesJson)

				return
			}

			//TODO live item while client is paused
			//TODO there must be some bug with connecting tokens that exists but with the wrong service
			for _, sbtCli := range server.sbtClients[(subchanId)] {
				if mConfiguration.Verbose { fmt.Printf("%s : SBT searching client: %s : %s\n", time.Now().Format(time.UnixDate), sbtCli.clientToken, reqClientToken) }
				if sbtCli.clientToken == reqClientToken {
					if mConfiguration.Verbose { fmt.Printf("%s : SBT found client at AFPos: %d\n", time.Now().Format(time.UnixDate), sbtCli.readAfs) }

					if action == "toggle" {
						if mConfiguration.Verbose { fmt.Printf("%s : ToggleCSeek to %d\n", time.Now().Format(time.UnixDate), wantedPosMs) }

						if wantedPosMs >= 0 && wantedPosMs <= sbtBuffers[subchanId].maxAfs {
							sbtCli.readAfs = uint64(wantedPosMs)

							rw.Header().Set("Cache-Control", "no-cache")
							rw.Header().Set("Connection", "close")
							rw.Header().Set("Access-Control-Allow-Origin", "*")
							_, _ = rw.Write(nil)
						} else {
							http.Error(rw, "Invalid toggle", http.StatusBadRequest)
						}

						break
					}

					if action == "seek" {
						sbtCli.bufferBurst = true

						//Read max timeshift time | maxAfs * 24 ms/AF
						maxTimeshiftTime := sbtBuffers[subchanId].maxTsMs

						if wantedUts >= 0 {
							if wantedUts >= 9999999999999 {
								if mConfiguration.Verbose {
									fmt.Printf("%s : Maximum timeshift length of %d exceeded: %d\n", time.Now().Format(time.UnixDate), maxTimeshiftTime, wantedPosMs)
								}
								http.Error(rw, "only seconds and microseconds wantedUts timestamps supported", http.StatusBadRequest)
								break
							}

							var wantedPosix time.Time
							if wantedUts > 9999999999 {
								wantedPosix = time.Unix(0, wantedUts*int64(time.Millisecond))
								fmt.Printf("%s : SeekPTS SBT millis: %s\n", time.Now().Format(time.UnixDate), wantedPosix.String())
							} else {
								wantedPosix = time.Unix(wantedUts, 0)
								fmt.Printf("%s : SeekPTS SBT second: %s\n", time.Now().Format(time.UnixDate), wantedPosix.String())
							}

							firstPosTime := sbtBuffers[subchanId].lastPosTime.Add(time.Millisecond * time.Duration(-sbtBuffers[subchanId].maxTsMs))
							if mConfiguration.Verbose {
								fmt.Printf("%s : SeekPTS SBT Fir: %s\n", time.Now().Format(time.UnixDate), firstPosTime.String())
							}
							if mConfiguration.Verbose {
								fmt.Printf("%s : SeekPTS SBT Max: %s\n", time.Now().Format(time.UnixDate), sbtBuffers[subchanId].lastPosTime.String())
							}

							var seekBuffPos uint64 = 0
							if wantedPosix.Before(firstPosTime) {
								//TODO the mod here may be wrong
								seekBuffPos = uint64((sbtBuffers[subchanId].buffPos + 1) % sbtBuffers[subchanId].maxAfs)
								if mConfiguration.Verbose {
									fmt.Printf("%s : SeekPTS SBT Zero CurBuffPos: %d, MaxAfs: %d, SeekPos: %d\n", time.Now().Format(time.UnixDate), sbtBuffers[subchanId].buffPos, sbtBuffers[subchanId].maxAfs, seekBuffPos)
								}

								sbtCli.readAfs = seekBuffPos

								rw.Header().Set("Cache-Control", "no-cache")
								rw.Header().Set("Connection", "close")
								rw.Header().Set("Access-Control-Allow-Origin", "*")
								_, _ = rw.Write(nil)

								break
							} else if wantedPosix.After(sbtBuffers[subchanId].lastPosTime) {
								if mConfiguration.Verbose {
									fmt.Printf("%s : SeekPTS SBT in the future seeking to realtime\n", time.Now().Format(time.UnixDate))
								}

								sbtCli.readAfs = uint64(sbtBuffers[subchanId].buffPos)

								rw.Header().Set("Cache-Control", "no-cache")
								rw.Header().Set("Connection", "close")
								rw.Header().Set("Access-Control-Allow-Origin", "*")
								_, _ = rw.Write(nil)

								break
							} else if (wantedPosix.Equal(firstPosTime) || wantedPosix.After(firstPosTime)) && (wantedPosix.Equal(sbtBuffers[subchanId].lastPosTime) || wantedPosix.Before(sbtBuffers[subchanId].lastPosTime)) {
								if mConfiguration.Verbose {
									fmt.Printf("%s : SeekPTS SBT is in range: %s - %d\n", time.Now().Format(time.UnixDate), sbtBuffers[subchanId].lastPosTime.Sub(wantedPosix).String(), sbtBuffers[subchanId].lastPosTime.Sub(wantedPosix).Milliseconds())
								}

								numAfsFromEnd := sbtBuffers[subchanId].lastPosTime.Sub(wantedPosix).Milliseconds() / 24
								if mConfiguration.Verbose { fmt.Printf("%s : SeekPTS SBT NumAfs from end: %d\n", time.Now().Format(time.UnixDate), numAfsFromEnd) }
								curBufPos := sbtBuffers[subchanId].buffPos

								if curBufPos-numAfsFromEnd < 0 {
									if mConfiguration.Verbose { fmt.Printf("%s : SeekPTS SBT seekBuffPos negative: %d\n", time.Now().Format(time.UnixDate), curBufPos-numAfsFromEnd) }
									seekBuffPos = uint64(sbtBuffers[subchanId].maxAfs + (curBufPos - numAfsFromEnd))
								} else {
									if mConfiguration.Verbose { fmt.Printf("%s : SeekPTS SBT seekBuffPos positive: %d\n", time.Now().Format(time.UnixDate), curBufPos-numAfsFromEnd) }
									seekBuffPos = uint64(curBufPos - numAfsFromEnd)
								}

								sbtCli.readAfs = seekBuffPos

								rw.Header().Set("Cache-Control", "no-cache")
								rw.Header().Set("Connection", "close")
								rw.Header().Set("Access-Control-Allow-Origin", "*")
								_, _ = rw.Write(nil)

								break
							}
						}

						if mConfiguration.Verbose { fmt.Printf("%s : MaxTimeshift Time: %d\n", time.Now().Format(time.UnixDate), maxTimeshiftTime) }
						//Convert wantedPos to AFs
						wantedPosAfs := wantedPosMs / 24
						if mConfiguration.Verbose { fmt.Printf("%s : WantedPos AFs: %d\n", time.Now().Format(time.UnixDate), wantedPosAfs) }
						// time from buffPos zero
						if wantedPosMs >= 0 {
							if wantedPosMs <= maxTimeshiftTime {
								//Realtime
								if wantedPosMs == 0 {
									sbtCli.readAfs = uint64(sbtBuffers[subchanId].buffPos)
								} else {
									curBufPos := sbtBuffers[subchanId].buffPos
									var wantedBuffPos uint64 = 0
									if curBufPos-wantedPosAfs < 0 {
										if mConfiguration.Verbose {
											fmt.Printf("%s : Buffer unwrap for CurPos: %d - WantedAfs: %d \n", time.Now().Format(time.UnixDate), curBufPos, wantedPosAfs)
										}
										wantedBuffPos = uint64(sbtBuffers[subchanId].maxAfs + (curBufPos - wantedPosAfs))
										if mConfiguration.Verbose {
											fmt.Printf("%s : Buffer unwrap to WantedBuffPos: %d - CurPos: %d\n", time.Now().Format(time.UnixDate), wantedBuffPos, curBufPos)
										}
									} else {
										wantedBuffPos = uint64(curBufPos - wantedPosAfs)
										if mConfiguration.Verbose {
											fmt.Printf("%s : Buffer to WantedBuffPos: %d - CurPos: %d\n", time.Now().Format(time.UnixDate), wantedBuffPos, curBufPos)
										}
									}

									sbtCli.readAfs = wantedBuffPos
								}

								rw.Header().Set("Cache-Control", "no-cache")
								rw.Header().Set("Connection", "close")
								rw.Header().Set("Access-Control-Allow-Origin", "*")
								_, _ = rw.Write(nil)
							} else {
								//write error
								if mConfiguration.Verbose { fmt.Printf("%s : Maximum timeshift length of %d exceeded: %d\n", time.Now().Format(time.UnixDate), maxTimeshiftTime, wantedPosMs) }
								http.Error(rw, "WantedPos exceeds maximum timeshift", http.StatusBadRequest)
							}
						} else {
							if mConfiguration.Verbose { fmt.Printf("%s : Negative wantedPos %d\n", time.Now().Format(time.UnixDate), wantedPosMs) }
							http.Error(rw, "Negative wantedPos", http.StatusBadRequest)
						}

						break
					}

					if action == "pause" {
						sbtCli.paused = true
						sbtCli.pauseHb = time.Now().Unix()
						break
					}

					if action == "play" {
						sbtCli.paused = false
						sbtCli.pauseHb = 0
						break
					}
				}
			}
		} else {
			http.Error(rw, "", http.StatusBadRequest)
		}
	}

	if req.Method == http.MethodGet {
		if mConfiguration.Verbose { fmt.Printf("%s : HTTP_GET method: %s %s\n", time.Now().Format(time.UnixDate), req.URL, req.Body) }
		flusher, ok := rw.(http.Flusher)

		if !ok {
			http.Error(rw, "Streaming unsupported!", http.StatusInternalServerError)
			return
		}

		id := strings.TrimPrefix(req.URL.Path, "/services/")
		if strings.Contains(id, "toggleslides") {
			if mConfiguration.Verbose { fmt.Printf("%s : GETREQ contains toggleslides\n", time.Now().Format(time.UnixDate)) }

			toggleReqSplit := strings.Split(id, "/")
			if len(toggleReqSplit) == 4 {
				toggleSlidePath := toggleReqSplit[1] + "/" + toggleReqSplit[2] + "/" + toggleReqSplit[3]
				if mConfiguration.Verbose { fmt.Printf("%s : GETREQ ToggleSlide reconstructed path: %s\n", time.Now().Format(time.UnixDate), toggleSlidePath) }

				rw.Header().Set("Cache-Control", "no-cache")
				rw.Header().Set("Connection", "close")
				rw.Header().Set("Access-Control-Allow-Origin", "*")

				if _, err := os.Stat(toggleSlidePath); !os.IsNotExist(err) {
					if mConfiguration.Verbose { fmt.Printf("%s : GETREQ file exists\n", time.Now().Format(time.UnixDate)) }

					imgData, err := ioutil.ReadFile(toggleSlidePath)
					if err != nil {
						if mConfiguration.Verbose { fmt.Printf("%s : GETREQ file read error: %s\n", time.Now().Format(time.UnixDate), err) }
					}

					_, _ = rw.Write(imgData)
					return
				} else {
					if mConfiguration.Verbose { fmt.Printf("%s : GETREQ file doesn't exists\n", time.Now().Format(time.UnixDate)) }
					http.Error(rw, "", http.StatusNotFound)
					//TODO how to kill connection
					//_, _ = rw.Write(nil)
					return
				}
			}
		}

		if id == "" {
			showOverviewPage(rw)
			return
		}

		subchanId, err := strconv.Atoi(id)

		if err != nil {
			showOverviewPage(rw)
			return
		}

		var srvAvailable bool

		FindSubchanFromSrvComp:
		for _, srv := range mDabServiceNew {
			for _, srvComp := range srv.DabServiceComponents {
				if srvComp.IsPrimary {
					if srvComp.SubChannelId == uint8(subchanId) {
						srvAvailable = true
						break FindSubchanFromSrvComp
					}
				}
			}
		}

		if !srvAvailable {
			if mConfiguration.Verbose { fmt.Printf("%s : No Service with SubchanID %d available\n", time.Now().Format(time.UnixDate), subchanId) }
			http.Error(rw, "", http.StatusBadRequest)
			return
		}

		if mConfiguration.Verbose { fmt.Printf("%s : ReqHdr: %s\n", time.Now().Format(time.UnixDate), req.Header) }

		var clientToken string
		query := req.URL.Query()

		clientToken = query.Get("timeshiftToken")
		if mConfiguration.Verbose { fmt.Printf("%s : GET TimeshiftToken: %s\n", time.Now().Format(time.UnixDate), clientToken) }

		wantedPosMsStr := query.Get("wantedPos")
		if mConfiguration.Verbose { fmt.Printf("%s : GET WantedPos: %s\n", time.Now().Format(time.UnixDate), wantedPosMsStr) }

		wantedPosMs, err := strconv.ParseInt(strings.TrimSpace(wantedPosMsStr), 10, 64)

		var wantedBuffPosValid = false
		var wantedBuffPos uint64 = 0
		if err == nil {
			maxTimeshiftTime := (sbtBuffers[uint8(subchanId)].maxAfs - 1) * 24

			wantedPosAfs := wantedPosMs / 24
			if wantedPosMs <= maxTimeshiftTime {
				if wantedPosMs >= 0 {
					curBufPos := sbtBuffers[uint8(subchanId)].buffPos

					if curBufPos-wantedPosAfs < 0 {
						if mConfiguration.Verbose { fmt.Printf("%s : Buffer unwrap for CurPos: %d - WantedAfs: %d \n", time.Now().Format(time.UnixDate), curBufPos, wantedPosAfs) }
						wantedBuffPos = uint64(sbtBuffers[uint8(subchanId)].maxAfs + (curBufPos - wantedPosAfs))
						if mConfiguration.Verbose { fmt.Printf("%s : Buffer unwrap to WantedBuffPos: %d - CurPos: %d\n", time.Now().Format(time.UnixDate), wantedBuffPos, curBufPos) }
					} else {
						wantedBuffPos = uint64(curBufPos - wantedPosAfs)
						if mConfiguration.Verbose { fmt.Printf("%s : Buffer to WantedBuffPos: %d - CurPos: %d\n", time.Now().Format(time.UnixDate), wantedBuffPos, curBufPos) }
					}

					wantedBuffPosValid = true
				}
			}
		} else {
			if mConfiguration.Verbose { fmt.Printf("%s : Error parsing wantedPos: %s\n", time.Now().Format(time.UnixDate), err) }
		}

		wantedUtsStr := query.Get("wantedUts")
		if mConfiguration.Verbose { fmt.Printf("GET UTS String: %s\n", wantedUtsStr) }
		wantedUts, err := strconv.ParseInt(wantedUtsStr, 10, 64)
		var utsPos uint64
		wantedUtsValid := false
		if err == nil {
			if wantedUts < 9999999999999 {
				var wantedPosix time.Time
				if wantedUts > 9999999999 {
					wantedPosix = time.Unix(0, wantedUts*int64(time.Millisecond))
					fmt.Printf("%s : GET UTS millis: %s\n", time.Now().Format(time.UnixDate), wantedPosix.String())
				} else {
					wantedPosix = time.Unix(wantedUts, 0)
					fmt.Printf("%s : GET UTS second: %s\n", time.Now().Format(time.UnixDate), wantedPosix.String())
				}

				firstPosTime := sbtBuffers[uint8(subchanId)].lastPosTime.Add(time.Millisecond * time.Duration(-sbtBuffers[uint8(subchanId)].maxTsMs))

				if wantedPosix.Before(firstPosTime) {
					if mConfiguration.Verbose { fmt.Printf("%s : GET UTS max SBT time setting to zero\n", time.Now().Format(time.UnixDate)) }

					utsPos = uint64((sbtBuffers[uint8(subchanId)].buffPos + 1) % sbtBuffers[uint8(subchanId)].maxAfs)

					wantedUtsValid = true
				} else if wantedPosix.After(sbtBuffers[uint8(subchanId)].lastPosTime) {
					utsPos = uint64(sbtBuffers[uint8(subchanId)].buffPos)
				} else if (wantedPosix.Equal(firstPosTime) || wantedPosix.After(firstPosTime)) && (wantedPosix.Equal(sbtBuffers[uint8(subchanId)].lastPosTime) || wantedPosix.Before(sbtBuffers[uint8(subchanId)].lastPosTime)) {
					if mConfiguration.Verbose { fmt.Printf("%s : GET UTS is in range: %s - %d\n", time.Now().Format(time.UnixDate), sbtBuffers[uint8(subchanId)].lastPosTime.Sub(wantedPosix).String(), sbtBuffers[uint8(subchanId)].lastPosTime.Sub(wantedPosix).Milliseconds()) }

					numAfsFromEnd := sbtBuffers[uint8(subchanId)].lastPosTime.Sub(wantedPosix).Milliseconds() / 24
					if mConfiguration.Verbose { fmt.Printf("%s : GET UTS NumAfs from end: %d\n", time.Now().Format(time.UnixDate), numAfsFromEnd) }
					curBufPos := sbtBuffers[uint8(subchanId)].buffPos

					if curBufPos - numAfsFromEnd < 0 {
						if mConfiguration.Verbose { fmt.Printf("%s : GET UTSseekBuffPos negative: %d\n", time.Now().Format(time.UnixDate), curBufPos - numAfsFromEnd) }
						utsPos = uint64(sbtBuffers[uint8(subchanId)].maxAfs + (curBufPos - numAfsFromEnd))
					} else {
						if mConfiguration.Verbose { fmt.Printf("%s : GET UTS seekBuffPos positive: %d\n", time.Now().Format(time.UnixDate), curBufPos - numAfsFromEnd) }
						utsPos = uint64(curBufPos - numAfsFromEnd)
					}

					wantedUtsValid = true
				}
			}
		}

		toggleStr := query.Get("toggleId")
		if mConfiguration.Verbose { fmt.Printf("%s : GET Toggle String: %s\n", time.Now().Format(time.UnixDate), toggleStr) }
		toggleId, err := strconv.ParseInt(toggleStr, 10, 64)
		toggleIdValid := false
		if err == nil {
			mToggleMapMutex.RLock()
			if _, toggleExists := mTogglesMap[uint8(subchanId)][toggleId]; toggleExists {
				if mConfiguration.Verbose { fmt.Printf("%s : Found GET Toggle: %d - %s\n", time.Now().Format(time.UnixDate), mTogglesMap[uint8(subchanId)][toggleId].ToggleId, mTogglesMap[uint8(subchanId)][toggleId].FullLabel) }

				//toggle sanity
				if toggleId <= int64(sbtBuffers[uint8(subchanId)].maxAfs) {
					toggleIdValid = true
				}
			}
			mToggleMapMutex.RUnlock()
		} else {
			if mConfiguration.Verbose { fmt.Printf("%s : Error parsing GET Toggle: %s\n", time.Now().Format(time.UnixDate), toggleStr) }
		}

		var tsClientFound bool
		var readAfs uint64
		messageChan := make(chan []byte, 1000) //addedBuffer for client-load testing

		//TODO timeshiftToken on wrong service valid
		for _, srchClientArr := range server.sbtClients {
			for _, srchClient := range srchClientArr {
				if srchClient.clientToken == clientToken {
					tsClientFound = true
					if wantedBuffPosValid {
						srchClient.readAfs = wantedBuffPos
					}

					if wantedUtsValid {
						if mConfiguration.Verbose { fmt.Printf("%s : Setting GET UTS: %d\n", time.Now().Format(time.UnixDate), utsPos) }
						srchClient.readAfs = utsPos
					}

					if toggleIdValid {
						if mConfiguration.Verbose { fmt.Printf("%s : Setting to GET Toggle: %d\n", time.Now().Format(time.UnixDate), toggleId) }
						srchClient.readAfs = uint64(toggleId)
					}

					srchClient.ediDataChan = append(srchClient.ediDataChan, messageChan)

					FindDabSrv:
					for _, dabSrv := range mDabServiceNew {
						for _, srvComp := range dabSrv.DabServiceComponents {
							if srvComp.SubChannelId == uint8(subchanId) {
								if mConfiguration.Verbose { fmt.Printf("%s : SBT Added existing Client sending DETIAF\n", time.Now().Format(time.UnixDate)) }
								for detiCnt := 0; detiCnt < 4; detiCnt++ {
									messageChan <- edisplitter.CreateDetiAF(dabSrv)
								}
								break FindDabSrv
							}
						}
					}

					if mConfiguration.Verbose { fmt.Printf("%s : Found already Existing SBT TsClient for token: %s at AF Position: %d\n", time.Now().Format(time.UnixDate), clientToken, srchClient.readAfs) }
					break
				}
			}
		}

		if !tsClientFound {
			clientToken = genSbtToken()
			if toggleIdValid {
				if mConfiguration.Verbose { fmt.Printf("%s : Setting initial GET Toggle: %d\n", time.Now().Format(time.UnixDate), toggleId) }
				readAfs = uint64(toggleId)
			} else if wantedUtsValid {
				if mConfiguration.Verbose { fmt.Printf("%s : Setting initial UTSPos to: %d\n", time.Now().Format(time.UnixDate), utsPos) }
				readAfs = utsPos
			} else if wantedBuffPosValid {
				if mConfiguration.Verbose { fmt.Printf("%s : Setting initial BuffPos to: %d\n", time.Now().Format(time.UnixDate), wantedBuffPos) }
				readAfs = wantedBuffPos
			} else {
				readAfs = uint64(sbtBuffers[uint8(subchanId)].buffPos - 1)
			}

			server.newClients <- func() (uint8, string, uint64, chan []byte) {
				return (uint8)(subchanId), clientToken, readAfs, messageChan
			}
		}

		if mConfiguration.Verbose { fmt.Printf("%s : ReqHdr Token: %s\n", time.Now().Format(time.UnixDate), clientToken) }

		rw.Header().Set("Content-Type", "audio/edi")
		rw.Header().Set("Cache-Control", "no-cache")
		rw.Header().Set("Connection", "keep-alive")
		rw.Header().Set("Access-Control-Allow-Origin", "*")

		//new SBT headers
		sbtBuffersMutex.RLock()
		if sbtBuffers[uint8(subchanId)].isTimeshiftable {
			//enable header visibility
			rw.Header().Set("Access-Control-Expose-Headers", "Timeshift-Token,Timeshift-Max")

			rw.Header().Set("Timeshift-Max", sbtBuffers[uint8(subchanId)].maxTsMsStr)
			rw.Header().Set("Timeshift-Token", clientToken)
		}
		sbtBuffersMutex.RUnlock()

		defer func() {
			server.closingClients <- func() (uint8, chan []byte) {
				return (uint8)(subchanId), messageChan
			}
		}()

		// Listen to connection close and un-register messageChan
		notify := rw.(http.CloseNotifier).CloseNotify()

		go func() {
			<-notify
			server.closingClients <- func() (uint8, chan []byte) {
				return (uint8)(subchanId), messageChan
			}
		}()

		//Read EdiFrames from the channel
		for {
			_, _ = rw.Write(<-messageChan)
			flusher.Flush()
		}
	}
}

func showOverviewPage(rw http.ResponseWriter) {
	var builder strings.Builder
	builder.WriteString("<html lang='en'>")

	if len(mDabServiceNew) > 0 {
		builder.WriteString("<b>")
		builder.WriteString("Ensemble: ")
		builder.WriteString(mDabServiceNew[0].EnsembleLabel)
		builder.WriteString(" - ")
		builder.WriteString(mDabServiceNew[0].EnsembleShortLabel)
		builder.WriteString("<br>")
		builder.WriteString("EnsembleId: 0x")
		builder.WriteString(strconv.FormatUint((uint64)(mDabServiceNew[0].EnsembleId), 16))
		builder.WriteString("<br>")
		builder.WriteString("EnsembleEcc: 0x")
		builder.WriteString(strconv.FormatUint((uint64)(mDabServiceNew[0].EnsembleEcc), 16))
		builder.WriteString("</b>")
		builder.WriteString("<br>")
		builder.WriteString("<br>")

		for _, srv := range mDabServiceNew {
			builder.WriteString("<b>")
			builder.WriteString("Service: ")
			builder.WriteString(srv.ServiceLabel)
			builder.WriteString(" - ")
			builder.WriteString(srv.ServiceShortLabel)
			builder.WriteString("</b>")
			builder.WriteString("<br>")

			builder.WriteString("ServiceId: 0x")
			builder.WriteString(strconv.FormatUint((uint64)(srv.ServiceId), 16))
			builder.WriteString("<br>")

			subchanId := uint8(0xFF)
			for _, srvComp := range srv.DabServiceComponents {
				if srvComp.IsPrimary {
					subchanId = srvComp.SubChannelId
				}
				builder.WriteString("<blockquote>")
				builder.WriteString("<b>")
				builder.WriteString("ServiceComponent")
				builder.WriteString("</b>")
				builder.WriteString("<br>")

				builder.WriteString("Label: ")
				builder.WriteString(srvComp.ServiceComponentLabel)
				builder.WriteString(" - ")
				builder.WriteString(srvComp.ServiceComponentShortLabel)
				builder.WriteString("<br>")

				builder.WriteString("SCIDs: 0x")
				builder.WriteString(strconv.FormatUint((uint64)(srvComp.SCIDs), 16))
				builder.WriteString("<br>")
				builder.WriteString("Primary: ")
				builder.WriteString(strconv.FormatBool(srvComp.IsPrimary))
				builder.WriteString("<br>")

				builder.WriteString("TMID: 0x")
				builder.WriteString(strconv.FormatUint((uint64)(srvComp.TransportModeId), 16))
				builder.WriteString(" - ")
				switch srvComp.TransportModeId {
				case 0:
					builder.WriteString("MSC Stream Audio")
				case 1:
					builder.WriteString("MSC Stream Data")
				case 3:
					builder.WriteString("MSC Packet Mode")
				}
				builder.WriteString("<br>")
				if srvComp.ASCTy != 0xFF {
					builder.WriteString("ASCTy: 0x")
					builder.WriteString(strconv.FormatUint((uint64)(srvComp.ASCTy), 16))
					if srvComp.ASCTy == 0 {
						builder.WriteString(" - DAB MPEG-1 Layer 2 Audio")
					} else {
						builder.WriteString(" - DAB+ AAC Audio")
					}
					builder.WriteString("<br>")
				}
				if srvComp.DSCTy != 0xFF {
					builder.WriteString("DSCTy: 0x")
					builder.WriteString(strconv.FormatUint((uint64)(srvComp.DSCTy), 16))
					builder.WriteString(" - ")
					switch srvComp.DSCTy {
					case 5:
						builder.WriteString("TDC - Transparent Data Channel")
					case 24:
						builder.WriteString("MPEG-2 Trasnport Stream")
					case 60:
						builder.WriteString("MOT - Multimedia Object Transfer")
					default:
						builder.WriteString("Unknown")
					}
					builder.WriteString("<br>")

					builder.WriteString("PacketAddress: ")
					builder.WriteString(strconv.FormatUint((uint64)(srvComp.PacketAddress), 10))
					builder.WriteString("<br>")
				}
				builder.WriteString("SubchannelID: 0x")
				builder.WriteString(strconv.FormatUint((uint64)(srvComp.Subchannel.SubchannelId), 16))
				builder.WriteString(" Dec: ")
				builder.WriteString(strconv.FormatUint((uint64)(srvComp.Subchannel.SubchannelId), 10))
				builder.WriteString("<br>")
				builder.WriteString("SubchannelBitrate: ")
				builder.WriteString(strconv.FormatUint(uint64(srvComp.Subchannel.SubchannelBitrate), 10))
				builder.WriteString(" kbit/s")

				for _, uApp := range srvComp.UserApplications {
					builder.WriteString("<blockquote>")
					builder.WriteString("<b>")
					builder.WriteString("User Application")
					builder.WriteString("</b>")
					builder.WriteString("<br>")
					builder.WriteString("Label: ")
					builder.WriteString(uApp.XpadAppLabel)
					builder.WriteString(" - ")
					builder.WriteString(uApp.XpadAppShortLabel)
					builder.WriteString("<br>")
					builder.WriteString("isXpadApp: ")
					builder.WriteString(strconv.FormatBool(uApp.IsXpadApp))
					builder.WriteString("<br>")
					if uApp.IsXpadApp {
						builder.WriteString("XPAD AppType: 0x")
						builder.WriteString(strconv.FormatUint((uint64)(uApp.XpadAppType), 16))
						builder.WriteString("<br>")
					}
					builder.WriteString("Type: 0x")
					builder.WriteString(strconv.FormatUint((uint64)(uApp.UAppType), 16))
					builder.WriteString(" - ")
					switch uApp.UAppType {
					case 2:
						builder.WriteString("SlideShow")
					case 4:
						builder.WriteString("TPEG")
					case 7:
						builder.WriteString("DMB")
					case 13:
						builder.WriteString("FileCasting")
					case 1098:
						builder.WriteString("Journaline")
					default:
						builder.WriteString("Unknown")
					}
					builder.WriteString("<br>")
					builder.WriteString("DSCTy: 0x")
					builder.WriteString(strconv.FormatUint((uint64)(uApp.DSCTy), 16))
					builder.WriteString(" - ")
					switch uApp.DSCTy {
					case 5:
						builder.WriteString("TDC - Transparent Data Channel")
					case 24:
						builder.WriteString("MPEG-2 Trasnport Stream")
					case 60:
						builder.WriteString("MOT - Multimedia Object Transfer")
					default:
						builder.WriteString("Unknown")
					}
					builder.WriteString("<br>")

					builder.WriteString("</blockquote>")
				}

				//builder.WriteString("<br>")
				builder.WriteString("</blockquote>")
			}

			if srv.IsProgramme {
				builder.WriteString("<b>Play: </b><br>")
				for _, address := range hostAddress {
					if len(address) > 0 {
						builder.WriteString("<a target='_blank' href='http://edistream.irt.de/tryme/?url=" + url.QueryEscape(address+":"+strconv.Itoa(mConfiguration.ProxyPort)+"/services/"+strconv.FormatUint((uint64)(subchanId), 10)) + "'>" + "Linear: " + address + "</a>")
						builder.WriteString("<br>")

						sbtBuffersMutex.RLock()
						if sbtBuffers[subchanId].isTimeshiftable {
							builder.WriteString("<a target='_blank' href='http://edistream.irt.de/sbt/?url=" + url.QueryEscape(address+":"+strconv.Itoa(mConfiguration.ProxyPort)+"/services/"+strconv.FormatUint((uint64)(subchanId), 10)) + "'>" + "SBT: " + address + "</a>")
							builder.WriteString("<br>")
						}
						sbtBuffersMutex.RUnlock()
					}
				}
			}

			builder.WriteString("<br>")

		}
		builder.WriteString("</html>")
		_, _ = fmt.Fprint(rw, builder.String())
	}
}

func genSbtToken() string {
	randBytes := make([]byte, 16)
	_, _ = rand.Read(randBytes)
	return base64.RawURLEncoding.EncodeToString(randBytes)
}

type sbtBuffer struct {
	startTime 		time.Time
	jumpPoints 		map[uint64]uint64
	afData 			[][]byte
	maxAfs 			int64
	maxTsMs			int64
	maxTsMsStr		string
	buffPos 		int64
	zeroAfNum		uint16
	isTimeshiftable	bool
	lastPosTime		time.Time
}

var (
	sbtBuffers map[uint8]*sbtBuffer
	sbtBuffersMutex = sync.RWMutex{}
)

func minutes2MsNumAfs(minutes int) (numAfs int64, ms int64, msStr string) {
	ms = int64(minutes) * 60 * 1000
	msStr = strconv.FormatInt(ms, 10)
	numAfs = int64(minutes) * 60 * 1000 / 24 //minutesSecondsMilliseconds divided by 24 ms per AF
	return
}

func handleStreamGoNew(server *StreamingServer, srv *edisplitter.DabSrv) {
	if sbtBuffers == nil {
		sbtBuffers = make(map[uint8]*sbtBuffer)
	}

	var subChanId uint8
	for _, srvCompPtr := range srv.DabServiceComponents {
		if srvCompPtr.IsPrimary {
			subChanId = srvCompPtr.SubChannelId
		}
	}

	for {
		ediData := <-srv.AfFrameOutput

		sbtBuffersMutex.Lock()
		if sbtBuffers[subChanId] == nil {
			newSbtBuffer := new(sbtBuffer)
			newSbtBuffer.startTime = time.Now()
			newSbtBuffer.buffPos = 0

			if _, subchanConfExists := mSbtConfig[subChanId]; subchanConfExists {
				numAfs, tsMs, tsMsStr := minutes2MsNumAfs(mSbtConfig[subChanId])

				if mConfiguration.Verbose { fmt.Printf("%s : Creating new SBTBuffer for SubchannelId: 0x%02x : %d with %d minutes or %d AFs, %d - %s of SBT\n", time.Now().Format(time.UnixDate), subChanId, subChanId, mSbtConfig[subChanId], numAfs, tsMs, tsMsStr) }

				newSbtBuffer.maxTsMs = tsMs
				newSbtBuffer.maxTsMsStr = tsMsStr
				newSbtBuffer.afData = make([][]byte, numAfs+1)
				newSbtBuffer.maxAfs = numAfs+1
				newSbtBuffer.isTimeshiftable = true
			} else {
				if mConfiguration.Verbose { fmt.Printf("%s : Creating new SBTBuffer for SubchannelId: 0x%02x : %d with 30 seconds of SBT\n", time.Now().Format(time.UnixDate), subChanId, subChanId) }
				newSbtBuffer.afData = make([][]byte, 1251)
				newSbtBuffer.maxAfs = 1251
				newSbtBuffer.isTimeshiftable = false
			}

			sbtBuffers[subChanId] = newSbtBuffer
		}
		sbtBuffersMutex.Unlock()

		//Get first AFSeqNum
		sbtBuffersMutex.Lock()
		if sbtBuffers[subChanId].buffPos == 0 {
			//ediData
			zeroAfSeqNum := binary.BigEndian.Uint16(ediData[6:8])
			if mConfiguration.Verbose { fmt.Printf("%s : ToggleC ZeroSeqNum for Subchan %d: %d\n", time.Now().Format(time.UnixDate), subChanId, zeroAfSeqNum) }
			sbtBuffers[subChanId].zeroAfNum = zeroAfSeqNum
			edisplitter.MAfWrapMultiMap[subChanId] = 0
		}

		sbtBuffers[subChanId].afData[sbtBuffers[subChanId].buffPos] = ediData
		sbtBuffers[subChanId].lastPosTime = time.Now()
		sbtBuffers[subChanId].buffPos++
		if sbtBuffers[subChanId].buffPos == sbtBuffers[subChanId].maxAfs {
			if mConfiguration.Verbose { fmt.Printf("%s : BufferWrap: %d - %s\n", time.Now().Format(time.UnixDate), len(sbtBuffers[subChanId].afData), time.Since(sbtBuffers[subChanId].startTime)) }
			sbtBuffers[subChanId].startTime = time.Now()
			sbtBuffers[subChanId].buffPos = 0
		}
		sbtBuffersMutex.Unlock()

		mToggleMapMutex.Lock()
		for k := range mTogglesMap[subChanId] {
			if k == sbtBuffers[subChanId].buffPos {

				slidePath := mTogglesMap[subChanId][k].SlidePath
				if len(slidePath) > 0 {
					if mConfiguration.Verbose { fmt.Printf("%s : ToggleRemove Slide from Path: %s\n", time.Now().Format(time.UnixDate), slidePath) }
					if mConfiguration.Verbose { fmt.Printf("%s : ToggleRemove Slide from Path: %s\n", time.Now().Format(time.UnixDate), slidePath) }

					remErr := os.Remove(slidePath[1:])
					if remErr != nil {
						if mConfiguration.Verbose { fmt.Printf("%s : ToggleRemove error removing saved file: %s\n", time.Now().Format(time.UnixDate), remErr) }
					}

					for idx, toggleMapper := range mTogglesSlideMap[subChanId] {
						if toggleMapper.toggleBuffPos == k {
							if mConfiguration.Verbose { fmt.Printf("%s : ToggleRemove SlideMapper at Idx: %d SliceIdx: %d\n", time.Now().Format(time.UnixDate), idx, idx+1) }
							mTogglesSlideMap[subChanId] = mTogglesSlideMap[subChanId][idx+1:]
							break
						}
					}
				}
				preDelLen := len(mTogglesMap[subChanId])
				delete(mTogglesMap[subChanId], k)
				postDelLen := len(mTogglesMap[subChanId])
				if mConfiguration.Verbose { fmt.Printf("%s : ToggleRemove for SubchanId 0x%02X at buffpos: %d, PreLen: %d, PostLen: %d\n", time.Now().Format(time.UnixDate), subChanId, sbtBuffers[subChanId].buffPos, preDelLen, postDelLen) }
				break
			}
		}
		mToggleMapMutex.Unlock()

		//check if a toggle is pending for the current subchan
		edisplitter.MPendingToggleMutex.RLock()
		liveTogglePending, _ := edisplitter.MPendingToggle[subChanId]
		edisplitter.MPendingToggleMutex.RUnlock()
		for stbClientIdx, sbtClient := range server.sbtClients[subChanId] {
			//TODO bufferburst
			if sbtClient != nil {
				if sbtClient.bufferBurst {
					/*
						if sbtClient.burstChan != nil {
							burst := 30*41
							burstStartPos := sbtClient.readAfs-uint64(burst)
							burstStartMod := int(burstStartPos) % sbtBuffers[subChanId].maxAfs
							fmt.Printf("%s : Bursting buffer at ReadAfs: %d, MaxAFs: %d, BuffPos: %d, BurstStartPos: %d, Mod: %d\n", time.Now().String(), sbtClient.readAfs, sbtBuffers[subChanId].maxAfs, sbtBuffers[subChanId].buffPos, burstStartPos, burstStartMod)

							for burst := 30*41; burst > 0; burst-- {
								fmt.Printf("%s : Bursting buffer %d - %d\n", time.Now().String(), burst, sbtClient.readAfs-uint64(burst))
								*sbtClient.burstChan <- sbtBuffers[subChanId].afData[sbtClient.readAfs-uint64(burst)]
							}

							fmt.Printf("%s : Bursting buffer....done\n", time.Now().String())

							sbtClient.bufferBurst = false
							sbtClient.burstChan = nil
						} else {
							fmt.Printf("%s : Bursting chan is nil\n", time.Now().String())
							sbtClient.bufferBurst = false
						}
					*/
					sbtClient.bufferBurst = false
					sbtClient.burstChan = nil
				}

				if !sbtClient.paused {
					if len(sbtClient.ediDataChan) > 0 {
						for _, sbtClientChan := range sbtClient.ediDataChan {
							if liveTogglePending != nil {
								origAfData := sbtBuffers[subChanId].afData[sbtClient.readAfs]
								customTag := edisplitter.CreateDlptTag(liveTogglePending)
								customizedAfFrame := edisplitter.InsertCustomLiveTag(origAfData, customTag)
								sbtClientChan <- customizedAfFrame
							} else {
								//TODO newSend
								if len(sbtClientChan) > 10 {
									fmt.Printf("ClientChanLen dangling buffer grows: %d\n", len(sbtClientChan))
								}
								if len(sbtClientChan) > 99 {
									fmt.Printf("ClientChanLen exceeds limit: %d\n", len(sbtClientChan))
									server.closingClients <- func() (uint8, chan []byte) {
										return subChanId, sbtClientChan
									}
								} else {
									sbtClientChan <- sbtBuffers[subChanId].afData[sbtClient.readAfs]
								}
							}
						}
						sbtClient.readAfs++

						if int64(sbtClient.readAfs) == sbtBuffers[subChanId].maxAfs {
							sbtClient.readAfs = 0
						}
					} else {
						if sbtBuffers[subChanId].buffPos == int64(sbtClient.readAfs) {
							if stbClientIdx < len(server.sbtClients[subChanId])-1 {
								copy(server.sbtClients[subChanId][stbClientIdx:], server.sbtClients[subChanId][stbClientIdx+1:])
							}
							server.sbtClients[subChanId][len(server.sbtClients[subChanId])-1] = nil // or the zero value of T
							server.sbtClients[subChanId] = server.sbtClients[subChanId][:len(server.sbtClients[subChanId])-1]

							fmt.Printf("%s : TimeshiftBuffer for Token: %s expired at: %d - %d. Clients Remaining: %d\n", time.Now().Format(time.UnixDate), sbtClient.clientToken, sbtBuffers[subChanId].buffPos, sbtClient.readAfs, len(server.sbtClients[subChanId]))
						}
					}
				} else {
					if sbtBuffers[subChanId].buffPos-1 == int64(sbtClient.readAfs) {
						fmt.Printf("%s : Maximum Pause time reached for client: %s at BuffPos: %d - ClientPos: %d\n", time.Now().Format(time.UnixDate), sbtClient.clientToken, sbtBuffers[subChanId].buffPos-1, sbtClient.readAfs)
						for _, closeClient := range sbtClient.ediDataChan {
							//TODO 100% CPU cause?
							//close(closeClient)

							server.closingClients <- func() (uint8, chan []byte) {
								return subChanId, closeClient
							}
						}

						server.sbtClients[subChanId] = append(server.sbtClients[subChanId][:stbClientIdx], server.sbtClients[subChanId][stbClientIdx+1:]...)
					} else {
						//TODO highly experimental. Send a livetoggle to paused client. May interrupt AF counter on different implementations
						if liveTogglePending != nil {
							fmt.Printf("%s : Inserting live toggle for paused client\n", time.Now().String())
							for _, sbtClientChan := range sbtClient.ediDataChan {
								origAfData := sbtBuffers[subChanId].afData[sbtClient.readAfs]
								customTag := edisplitter.CreateDlptTag(liveTogglePending)
								customizedAfFrame := edisplitter.InsertCustomLiveTag(origAfData, customTag)
								sbtClientChan <- customizedAfFrame
							}
						}
						//TODO highly experimental. Send some heartbeat data to prevent socket timeouts
						nowTime := time.Now().Unix()
						if nowTime > sbtClient.pauseHb {
							heartBeat := []byte{'P', 'F', 0x00, 0x00}
							for _, sbtClientChan := range sbtClient.ediDataChan {
								sbtClientChan <- heartBeat
							}
							sbtClient.pauseHb = nowTime
						}
					}
				}
			}
		}
		//set live toggle to nil
		if liveTogglePending != nil {
			edisplitter.MPendingToggleMutex.Lock()
			edisplitter.MPendingToggle[subChanId] = nil
			edisplitter.MPendingToggleMutex.Unlock()
		}
	}
}