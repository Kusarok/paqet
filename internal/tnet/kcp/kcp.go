package kcp

import (
	"math/rand"
	"paqet/internal/conf"
	"time"

	"github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/smux"
)

func aplConf(conn *kcp.UDPSession, cfg *conf.KCP) {
	var noDelay, interval, resend, noCongestion int
	var wDelay, ackNoDelay bool
	switch cfg.Mode {
	case "normal":
		noDelay, interval, resend, noCongestion = 0, 40, 2, 1
		wDelay, ackNoDelay = true, false
	case "fast":
		noDelay, interval, resend, noCongestion = 0, 30, 2, 1
		wDelay, ackNoDelay = true, false
	case "fast2":
		noDelay, interval, resend, noCongestion = 1, 20, 2, 1
		wDelay, ackNoDelay = false, true
	case "fast3":
		noDelay, interval, resend, noCongestion = 1, 10, 2, 1
		wDelay, ackNoDelay = false, true
	}

	// Add jitter to interval for timing obfuscation
	intervalJitter := interval + rand.Intn(5) - 2 // ±2ms randomness
	if intervalJitter < 5 {
		intervalJitter = 5
	}
	
	conn.SetNoDelay(noDelay, intervalJitter, resend, noCongestion)
	conn.SetWindowSize(cfg.Sndwnd, cfg.Rcvwnd)
	conn.SetMtu(cfg.MTU)
	conn.SetWriteDelay(wDelay)
	conn.SetACKNoDelay(ackNoDelay)
	
	// Randomize DSCP to avoid fingerprinting (0=normal, 8=CS1, 10=AF11, 18=AF21)
	dscpValues := []int{0, 0, 0, 8, 10, 18} // Weighted towards 0 (normal traffic)
	conn.SetDSCP(dscpValues[rand.Intn(len(dscpValues))])
}

func smuxConf(cfg *conf.KCP) *smux.Config {
	var sconf = smux.DefaultConfig()
	sconf.Version = 2
	sconf.KeepAliveInterval = 2 * time.Second
	sconf.KeepAliveTimeout = 8 * time.Second
	sconf.MaxFrameSize = 65535
	sconf.MaxReceiveBuffer = cfg.Smuxbuf
	sconf.MaxStreamBuffer = cfg.Streambuf
	return sconf
}
