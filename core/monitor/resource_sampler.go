package monitor

import (
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

var reSamplerNetIface = regexp.MustCompile(`^\s*(eth0|ens\d+|enp\d+s\d+)\s*:\s*(\d+)\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)`)

type resourceSample struct {
	CPURaw     *CPURaw
	CPUPct     float64
	Memory     MemStat
	MemFree    int64
	MemBuffers int64
	MemCached  int64
	MemAvail   int64
	Swap       MemStat
	SwapFree   int64
	Network    NetStat
	Load       LoadStat
	Timestamp  int64
}

type resourceSampler struct {
	mu       sync.RWMutex
	interval time.Duration
	prevRaw  *CPURaw
	sample   resourceSample
	inited   bool
}

var (
	rtSamplerOnce sync.Once
	rtSampler     = &resourceSampler{interval: 5 * time.Second}
)

func getResourceSample() resourceSample {
	rtSampler.ensureStarted()
	return rtSampler.get()
}

func (s *resourceSampler) ensureStarted() {
	rtSamplerOnce.Do(func() {
		s.updateOnce()
		go s.loop()
	})
}

func (s *resourceSampler) loop() {
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for range ticker.C {
		s.updateOnce()
	}
}

func (s *resourceSampler) get() resourceSample {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := s.sample
	if out.CPURaw != nil {
		cp := *out.CPURaw
		out.CPURaw = &cp
	}
	return out
}

func (s *resourceSampler) updateOnce() {
	raw := readCPURaw()
	if raw == nil {
		return
	}
	memTotal, memFree, memBuffers, memCached, memAvail, swapTotal, swapFree := readMemSnapshot()
	memUsed := memTotal - memFree - memBuffers - memCached
	if memUsed < 0 {
		memUsed = 0
	}
	memPct := pct(memUsed, memTotal)
	swapUsed := swapTotal - swapFree
	if swapUsed < 0 {
		swapUsed = 0
	}
	swapPct := pct(swapUsed, swapTotal)
	load := readLoadSnapshot()
	net := readNetSnapshot()
	now := time.Now().Unix()

	s.mu.Lock()
	defer s.mu.Unlock()

	cpuPct := s.sample.CPUPct
	if s.prevRaw != nil {
		cpuPct = cpuUsageDiffPct(*s.prevRaw, *raw)
	}
	cp := *raw
	s.prevRaw = &cp
	cur := cp
	s.sample = resourceSample{
		CPURaw: &cur,
		CPUPct: cpuPct,
		Memory: MemStat{
			Total: memTotal,
			Used:  memUsed,
			Pct:   memPct,
		},
		MemFree:    memFree,
		MemBuffers: memBuffers,
		MemCached:  memCached,
		MemAvail:   memAvail,
		Swap: MemStat{
			Total: swapTotal,
			Used:  swapUsed,
			Pct:   swapPct,
		},
		SwapFree:  swapFree,
		Network:   net,
		Load:      load,
		Timestamp: now,
	}
	s.inited = true
}

func readCPURaw() *CPURaw {
	raw, err := os.ReadFile("/proc/stat")
	if err != nil {
		return nil
	}
	re := regexp.MustCompile(`^cpu\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)`)
	for _, line := range strings.Split(string(raw), "\n") {
		m := re.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pi := func(v string) int64 {
			n, _ := strconv.ParseInt(v, 10, 64)
			return n
		}
		return &CPURaw{
			User:    pi(m[1]),
			Nice:    pi(m[2]),
			System:  pi(m[3]),
			Idle:    pi(m[4]),
			IOWait:  pi(m[5]),
			IRQ:     pi(m[6]),
			SoftIRQ: pi(m[7]),
			Steal:   pi(m[8]),
		}
	}
	return nil
}

func readMemSnapshot() (memTotal, memFree, memBuffers, memCached, memAvail, swapTotal, swapFree int64) {
	mi, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(mi), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		val, _ := strconv.ParseInt(fields[1], 10, 64)
		val *= 1024 // kB -> bytes
		switch fields[0] {
		case "MemTotal:":
			memTotal = val
		case "MemFree:":
			memFree = val
		case "Buffers:":
			memBuffers = val
		case "Cached:":
			memCached += val
		case "SReclaimable:":
			memCached += val
		case "MemAvailable:":
			memAvail = val
		case "SwapTotal:":
			swapTotal = val
		case "SwapFree:":
			swapFree = val
		}
	}
	return
}

func readLoadSnapshot() LoadStat {
	load := LoadStat{}
	la, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return load
	}
	parts := strings.Fields(string(la))
	if len(parts) >= 3 {
		load.Min1, _ = strconv.ParseFloat(parts[0], 64)
		load.Min5, _ = strconv.ParseFloat(parts[1], 64)
		load.Min15, _ = strconv.ParseFloat(parts[2], 64)
	}
	return load
}

func readNetSnapshot() NetStat {
	net := NetStat{}
	netRaw, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return net
	}
	for _, line := range strings.Split(string(netRaw), "\n") {
		if m := reSamplerNetIface.FindStringSubmatch(line); m != nil {
			rx, _ := strconv.ParseFloat(m[2], 64)
			tx, _ := strconv.ParseFloat(m[3], 64)
			net = NetStat{RX: rx, TX: tx, Iface: m[1]}
			break
		}
	}
	return net
}

func cpuUsageDiffPct(prev, cur CPURaw) float64 {
	prevIdle := prev.Idle + prev.IOWait
	curIdle := cur.Idle + cur.IOWait
	prevTotal := prev.User + prev.Nice + prev.System + prevIdle + prev.IRQ + prev.SoftIRQ + prev.Steal
	curTotal := cur.User + cur.Nice + cur.System + curIdle + cur.IRQ + cur.SoftIRQ + cur.Steal
	totalDiff := curTotal - prevTotal
	idleDiff := curIdle - prevIdle
	if totalDiff <= 0 {
		return 0
	}
	v := float64(totalDiff-idleDiff) / float64(totalDiff) * 100
	if v < 0 {
		v = 0
	}
	if v > 100 {
		v = 100
	}
	return math.Round(v*10) / 10
}

func pct(used, total int64) float64 {
	if total <= 0 {
		return 0
	}
	return math.Round(float64(used)/float64(total)*1000) / 10
}
