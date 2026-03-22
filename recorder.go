package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pion/webrtc/v4"
)

// Recorder manages a single WebRTC recording session.
type Recorder struct {
	cfg *Config
	sdm *SDMClient

	pc             *webrtc.PeerConnection
	ffmpeg         *exec.Cmd
	videoUDP       *net.UDPConn
	audioUDP       *net.UDPConn
	videoTrack     *webrtc.TrackRemote
	audioTrack     *webrtc.TrackRemote
	videoPort      int
	audioPort      int
	mediaSessionID string
	streamExpires  time.Time
	mu             sync.Mutex

	startOnce  sync.Once
	ffWaitOnce sync.Once
	ffWaitErr  error
	errorChan  chan error
	ctx        context.Context
	cancel     context.CancelFunc
}

// NewRecorder creates a Recorder bound to the given context.
func NewRecorder(ctx context.Context, cfg *Config, sdm *SDMClient) *Recorder {
	recCtx, recCancel := context.WithCancel(ctx)
	return &Recorder{
		cfg:       cfg,
		sdm:       sdm,
		errorChan: make(chan error, 3),
		ctx:       recCtx,
		cancel:    recCancel,
	}
}

// waitFFmpeg calls Wait() on the ffmpeg process exactly once, returning the cached result.
func (r *Recorder) waitFFmpeg() error {
	r.ffWaitOnce.Do(func() {
		r.ffWaitErr = r.ffmpeg.Wait()
	})
	return r.ffWaitErr
}

// freeUDPPort returns an available UDP port number.
func freeUDPPort() (int, error) {
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return 0, err
	}
	p := l.LocalAddr().(*net.UDPAddr).Port
	_ = l.Close()
	return p, nil
}

// waitUDPPortListening polls /proc/net/udp until the given port appears as a
// local-address, meaning ffmpeg has opened its UDP listener.  This avoids
// sending any probe data that could corrupt ffmpeg's RTP sequence tracking.
//
// Two-phase approach:
//  1. Briefly wait for any stale entry to disappear (from freeUDPPort's
//     recently-closed listener socket).  Capped at 200ms because kernel
//     socket close is near-instant; if the port is still present after that,
//     it is ffmpeg's real listener, not a stale entry.
//  2. Wait for ffmpeg's new listener to appear.
func waitUDPPortListening(ctx context.Context, port int, timeout time.Duration) error {
	// Port number in /proc/net/udp is in hex, column 2 (local_address).
	// Format: "  sl  local_address ..."  e.g. " 0: 0100007F:D4E6 ..."
	target := fmt.Sprintf(":%04X ", port)

	deadline := time.Now().Add(timeout)

	// Phase 1: drain any stale entry left by freeUDPPort's closed socket.
	// Cap at 200ms — if the port is still listed after that, it belongs to
	// ffmpeg (which may have opened its listener while we were checking
	// the other port), so fall through to phase 2 which will find it.
	staleDeadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(staleDeadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		data, _ := os.ReadFile("/proc/net/udp")
		if !strings.Contains(string(data), target) {
			break // stale entry is gone (or was never there)
		}
		time.Sleep(5 * time.Millisecond)
	}

	// Phase 2: wait for ffmpeg to open its listener on the port.
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		data, err := os.ReadFile("/proc/net/udp")
		if err != nil {
			return fmt.Errorf("read /proc/net/udp: %w", err)
		}
		if strings.Contains(string(data), target) {
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("port %d not listening after %v", port, timeout)
}

// forwardRTP reads RTP packets from a WebRTC track and writes them to a UDP connection.
// The caller must ensure the UDP port is already open (see waitUDPPortListening).
// It stops when the context is cancelled and reports errors via errorChan.
//
// On startup pion will have buffered RTP packets while ffmpeg was initialising.
// Forwarding them as an instant burst overwhelms ffmpeg's RTP jitter buffer.
// To avoid this we collect the buffered packets, sort them by RTP sequence
// number (fixing any network reordering), and forward them with a small
// inter-packet delay so ffmpeg can process them cleanly.  SPS/PPS and IDR
// packets are preserved, so ffmpeg can initialise the H.264 decoder
// immediately.
func (r *Recorder) forwardRTP(track *webrtc.TrackRemote, conn *net.UDPConn, label string) {
	// Decouple blocking ReadRTP from select-based collect/forward logic.
	type pktOrErr struct {
		raw []byte
		err error
	}
	ch := make(chan pktOrErr, 500)
	go func() {
		for {
			pkt, _, err := track.ReadRTP()
			if err != nil {
				ch <- pktOrErr{err: err}
				return
			}
			raw, merr := pkt.Marshal()
			if merr != nil {
				continue
			}
			ch <- pktOrErr{raw: raw}
		}
	}()

	// Collect packets buffered in pion during ffmpeg startup (200ms).
	collectDone := time.After(200 * time.Millisecond)
	var buffered [][]byte
Collect:
	for {
		select {
		case <-r.ctx.Done():
			log.Printf("[RTC] %s forwarder stopped by context", label)
			return
		case <-collectDone:
			break Collect
		case p := <-ch:
			if p.err != nil {
				if r.ctx.Err() != nil {
					return
				}
				log.Printf("[RTC] %s ReadRTP: %v", label, p.err)
				select {
				case r.errorChan <- fmt.Errorf("%s ReadRTP: %w", label, p.err):
				default:
				}
				return
			}
			buffered = append(buffered, p.raw)
		}
	}

	// Sort buffered packets by RTP sequence number (bytes 2-3 of the
	// RTP header) to correct any network reordering from the burst.
	sort.Slice(buffered, func(i, j int) bool {
		si := uint16(buffered[i][2])<<8 | uint16(buffered[i][3])
		sj := uint16(buffered[j][2])<<8 | uint16(buffered[j][3])
		return si < sj
	})

	// Forward buffered packets with 1ms spacing so ffmpeg's jitter
	// buffer can absorb them without "dropping old packet" errors.
	log.Printf("[RTC] %s forwarding %d buffered packets", label, len(buffered))
	for _, raw := range buffered {
		if _, err := conn.Write(raw); err != nil {
			if r.ctx.Err() != nil {
				return
			}
			log.Printf("[UDP] %s write: %v", label, err)
			select {
			case r.errorChan <- fmt.Errorf("%s UDP write: %w", label, err):
			default:
			}
			return
		}
		time.Sleep(time.Millisecond)
	}

	// Forward live packets to ffmpeg at their natural arrival rate.
	for {
		select {
		case <-r.ctx.Done():
			log.Printf("[RTC] %s forwarder stopped by context", label)
			return
		case p := <-ch:
			if p.err != nil {
				if r.ctx.Err() != nil {
					return
				}
				log.Printf("[RTC] %s ReadRTP: %v", label, p.err)
				select {
				case r.errorChan <- fmt.Errorf("%s ReadRTP: %w", label, p.err):
				default:
				}
				return
			}
			if _, err := conn.Write(p.raw); err != nil {
				if r.ctx.Err() != nil {
					return
				}
				log.Printf("[UDP] %s write: %v", label, err)
				select {
				case r.errorChan <- fmt.Errorf("%s UDP write: %w", label, err):
				default:
				}
				return
			}
		}
	}
}

// startFFMPEG is called once both video & audio tracks are available.
func (r *Recorder) startFFMPEG() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ffmpeg != nil {
		return nil
	}

	var err error

	sdp := generateUnifiedSDP(r.videoTrack, r.videoPort, r.audioTrack, r.audioPort)

	if err = os.MkdirAll(r.cfg.OutputDir, 0o775); err != nil {
		return err
	}
	segTemplate := filepath.Join(r.cfg.OutputDir, "%Y-%m-%d_%H-%M-%S.mp4")
	vf := `drawtext=` +
		`fontfile=` + r.cfg.FontPath + `:` +
		`text='%{localtime\:%Y-%m-%d %H\\\:%M\\\:%S}':` +
		`x=w-text_w-20:y=h-text_h-20:` +
		`fontsize=24:fontcolor=white:` +
		`shadowcolor=black:shadowx=2:shadowy=2:` +
		`box=1:boxcolor=black@0.4`

	ff := exec.Command("ffmpeg",
		"-loglevel", "warning",
		"-protocol_whitelist", "file,udp,rtp,pipe",
		"-fflags", "+genpts",
		"-analyzeduration", "2000000",
		"-probesize", "10000000",
		"-f", "sdp", "-i", "pipe:0",
		"-vf", vf,
		"-c:v", "libx264", "-preset", "veryfast",
		"-c:a", "aac",
		"-movflags", "+faststart", "-reset_timestamps", "1",
		"-f", "segment", "-segment_time", fmt.Sprint(r.cfg.SegmentSeconds), "-strftime", "1",
		segTemplate,
	)
	stdin, err := ff.StdinPipe()
	if err != nil {
		return fmt.Errorf("ffmpeg StdinPipe: %w", err)
	}
	ff.Stderr = os.Stderr
	if err = ff.Start(); err != nil {
		return fmt.Errorf("ffmpeg start: %w", err)
	}
	_, _ = io.WriteString(stdin, sdp)
	_ = stdin.Close()
	r.ffmpeg = ff
	log.Printf("[FFMPEG] started pid %d", ff.Process.Pid)

	// Block until ffmpeg has opened both UDP listeners so the first
	// RTP packets (containing H.264 SPS/PPS) are not silently dropped.
	// Uses /proc/net/udp to detect without sending any probe data that
	// would corrupt ffmpeg's RTP sequence tracking.
	// IMPORTANT: DialUDP must happen AFTER this check, because a connected
	// UDP socket's remote-address field in /proc/net/udp would cause a
	// false-positive match on the target port.
	const portTimeout = 5 * time.Second
	if err = waitUDPPortListening(r.ctx, r.videoPort, portTimeout); err != nil {
		return fmt.Errorf("video port not ready: %w", err)
	}
	if err = waitUDPPortListening(r.ctx, r.audioPort, portTimeout); err != nil {
		return fmt.Errorf("audio port not ready: %w", err)
	}
	log.Println("[FFMPEG] UDP ports ready, starting RTP forwarding")

	// Now create the connected UDP sockets for forwarding.
	r.videoUDP, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.videoPort})
	if err != nil {
		return fmt.Errorf("video DialUDP: %w", err)
	}
	r.audioUDP, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.audioPort})
	if err != nil {
		return fmt.Errorf("audio DialUDP: %w", err)
	}

	go r.forwardRTP(r.videoTrack, r.videoUDP, "video")
	go r.forwardRTP(r.audioTrack, r.audioUDP, "audio")

	// Monitor ffmpeg process for unexpected termination
	go func() {
		err := r.waitFFmpeg()
		if r.ctx.Err() != nil {
			return // intentional shutdown
		}
		log.Printf("[FFMPEG] process exited unexpectedly: %v", err)
		select {
		case r.errorChan <- fmt.Errorf("ffmpeg exited: %w", err):
		default:
		}
	}()

	return nil
}

// Negotiate establishes a WebRTC connection and starts stream recording.
func (r *Recorder) Negotiate(ctx context.Context) error {
	m := webrtc.MediaEngine{}
	if err := m.RegisterDefaultCodecs(); err != nil {
		return err
	}
	api := webrtc.NewAPI(webrtc.WithMediaEngine(&m))
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return err
	}
	r.pc = pc

	if _, err = pc.AddTransceiverFromKind(webrtc.RTPCodecTypeAudio,
		webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		return fmt.Errorf("add audio transceiver: %w", err)
	}
	if _, err = pc.AddTransceiverFromKind(webrtc.RTPCodecTypeVideo,
		webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly}); err != nil {
		return fmt.Errorf("add video transceiver: %w", err)
	}
	if _, err = pc.CreateDataChannel("data", nil); err != nil {
		return fmt.Errorf("create data channel: %w", err)
	}

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Printf("[RTC] connection state: %s", state.String())
		if state == webrtc.PeerConnectionStateFailed ||
			state == webrtc.PeerConnectionStateDisconnected ||
			state == webrtc.PeerConnectionStateClosed {
			select {
			case r.errorChan <- fmt.Errorf("peer connection state: %s", state.String()):
			default:
			}
		}
	})

	pc.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		log.Printf("[RTC] track arrived: %s pt=%d", track.Kind(), track.PayloadType())
		r.mu.Lock()
		switch track.Kind() {
		case webrtc.RTPCodecTypeVideo:
			if p, err := freeUDPPort(); err == nil {
				r.videoPort = p
			}
			r.videoTrack = track
		case webrtc.RTPCodecTypeAudio:
			if p, err := freeUDPPort(); err == nil {
				r.audioPort = p
			}
			r.audioTrack = track
		}
		ready := r.videoTrack != nil && r.audioTrack != nil
		r.mu.Unlock()
		if ready {
			r.startOnce.Do(func() {
				go func() {
					if err := r.startFFMPEG(); err != nil {
						log.Println("[ERROR] startFFMPEG:", err)
						select {
						case r.errorChan <- fmt.Errorf("startFFMPEG: %w", err):
						default:
						}
					}
				}()
			})
		}
	})

	offer, err := pc.CreateOffer(nil)
	if err != nil {
		return fmt.Errorf("create offer: %w", err)
	}
	gather := webrtc.GatheringCompletePromise(pc)
	if err = pc.SetLocalDescription(offer); err != nil {
		return fmt.Errorf("set local description: %w", err)
	}
	select {
	case <-gather:
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
		return fmt.Errorf("ICE gathering timeout")
	}

	res, err := unmarshalCommand[streamResponse](ctx, r.sdm,
		"sdm.devices.commands.CameraLiveStream.GenerateWebRtcStream",
		map[string]any{"offerSdp": pc.LocalDescription().SDP},
	)
	if err != nil {
		return err
	}
	if err = pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  res.AnswerSDP,
	}); err != nil {
		return fmt.Errorf("set remote description: %w", err)
	}
	r.mediaSessionID = res.MediaSession
	exp, err := time.Parse(time.RFC3339, res.ExpiresAt)
	if err != nil {
		return fmt.Errorf("parse expiresAt %q: %w", res.ExpiresAt, err)
	}
	r.streamExpires = exp
	log.Printf("[RTC] stream valid until %s", r.streamExpires.Format(time.RFC3339))
	return nil
}

// Extend renews the WebRTC stream session before it expires.
func (r *Recorder) Extend(ctx context.Context) error {
	res, err := unmarshalCommand[streamResponse](ctx, r.sdm,
		"sdm.devices.commands.CameraLiveStream.ExtendWebRtcStream",
		map[string]any{"mediaSessionId": r.mediaSessionID},
	)
	if err != nil {
		return err
	}
	r.mediaSessionID = res.MediaSession
	exp, err := time.Parse(time.RFC3339, res.ExpiresAt)
	if err != nil {
		return fmt.Errorf("parse expiresAt %q: %w", res.ExpiresAt, err)
	}
	r.streamExpires = exp
	log.Printf("[RTC] extended; valid until %s", r.streamExpires.Format(time.RFC3339))
	return nil
}

// Close tears down the recording session, stopping goroutines and ffmpeg.
func (r *Recorder) Close() {
	if r.cancel != nil {
		r.cancel()
	}
	if r.pc != nil {
		_ = r.pc.Close()
	}
	if r.videoUDP != nil {
		_ = r.videoUDP.Close()
	}
	if r.audioUDP != nil {
		_ = r.audioUDP.Close()
	}
	if r.ffmpeg != nil && r.ffmpeg.Process != nil {
		_ = r.ffmpeg.Process.Signal(syscall.SIGINT)
		_ = r.waitFFmpeg()
	}
}
