package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"gopkg.in/yaml.v3"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pion/webrtc/v4"
)

// ---------------------------- CONFIG ---------------------------------------
type Config struct {
	ClientID            string `json:"client_id"            yaml:"client_id"`
	ClientSecret        string `json:"client_secret"        yaml:"client_secret"`
	RefreshToken        string `json:"refresh_token"        yaml:"refresh_token"`
	DeviceID            string `json:"device_id"            yaml:"device_id"`
	OutputDir           string `json:"output_dir"           yaml:"output_dir"`
	SegmentSeconds      int    `json:"segment_seconds"      yaml:"segment_seconds"`
	ExtendMarginSeconds int    `json:"extend_margin_seconds" yaml:"extend_margin_seconds"`
}

var cfg Config

func LoadConfig(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	switch ext := filepath.Ext(path); ext {
	case ".yaml", ".yml":
		if err = yaml.NewDecoder(f).Decode(&cfg); err != nil {
			return nil, err
		}
	case ".json":
		if err = json.NewDecoder(f).Decode(&cfg); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported config type: %s", ext)
	}
	return &cfg, nil
}

// ---------------------------------------------------------------------------
var httpClient = &http.Client{Timeout: 20 * time.Second}

// ---------------- OAuth2 ----------------------------------------------------
var (
	bearerToken   string
	bearerExpires time.Time
	tokenMu       sync.Mutex
)

func refreshAccessToken(ctx context.Context) error {
	data := url.Values{
		"client_id":     {cfg.ClientID},
		"client_secret": {cfg.ClientSecret},
		"refresh_token": {cfg.RefreshToken},
		"grant_type":    {"refresh_token"},
	}.Encode()

	req, _ := http.NewRequestWithContext(ctx, "POST", "https://oauth2.googleapis.com/token", strings.NewReader(data))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("token resp %d: %s", resp.StatusCode, body)
	}

	var tok struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&tok); err != nil {
		return err
	}

	tokenMu.Lock()
	bearerToken = tok.AccessToken
	bearerExpires = time.Now().Add(time.Duration(tok.ExpiresIn-60) * time.Second)
	tokenMu.Unlock()

	log.Printf("[AUTH] got token, valid %ds", tok.ExpiresIn)
	return nil
}

func getBearer(ctx context.Context) (string, error) {
	tokenMu.Lock()
	expired := bearerToken == "" || time.Now().After(bearerExpires)
	tokenMu.Unlock()
	if expired {
		if err := refreshAccessToken(ctx); err != nil {
			return "", err
		}
	}
	tokenMu.Lock()
	t := bearerToken
	tokenMu.Unlock()
	return t, nil
}

// ---------------- SDM helpers ----------------------------------------------
func executeCommand(ctx context.Context, command string, params any) (json.RawMessage, error) {
	url := fmt.Sprintf("https://smartdevicemanagement.googleapis.com/v1/%s:executeCommand", cfg.DeviceID)
	body, _ := json.Marshal(map[string]any{"command": command, "params": params})

	bearer, err := getBearer(ctx)
	if err != nil {
		return nil, err
	}

	req, _ := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("SDM %s -> %d: %s", command, resp.StatusCode, raw)
	}

	var res struct {
		Results json.RawMessage `json:"results"`
	}
	if err = json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, err
	}
	return res.Results, nil
}

func unmarshalCommand[T any](ctx context.Context, cmd string, params any) (T, error) {
	var v T
	raw, err := executeCommand(ctx, cmd, params)
	if err != nil {
		return v, err
	}
	err = json.Unmarshal(raw, &v)
	return v, err
}

// ---------------------------------------------------------------------------
// Recorder
// ---------------------------------------------------------------------------

type Recorder struct {
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
	mu             sync.Mutex // protect ffmpeg start

	startOnce sync.Once
	// ------------------------------------------------------------------
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

// generateUnifiedSDP builds an SDP describing "video + audio" streams.
func generateUnifiedSDP(v *webrtc.TrackRemote, vPort int,
	a *webrtc.TrackRemote, aPort int) string {

	vpt := v.PayloadType()
	vfmt := v.Codec().SDPFmtpLine
	if !strings.Contains(vfmt, "packetization-mode") {
		vfmt = "packetization-mode=1; " + vfmt
	}

	apt := a.PayloadType()
	acodec := strings.ToUpper(strings.Split(a.Codec().MimeType, "/")[1]) // OPUS
	ach := a.Codec().Channels
	arv := a.Codec().ClockRate
	afmt := a.Codec().SDPFmtpLine

	return fmt.Sprintf(`v=0
o=- 0 0 IN IP4 127.0.0.1
s=NestCam
c=IN IP4 127.0.0.1
t=0 0
m=audio %d RTP/AVP %d
a=rtpmap:%d %s/%d/%d
%s
m=video %d RTP/AVP %d
a=rtpmap:%d H264/90000
a=fmtp:%d %s
`, aPort, apt,
		apt, acodec, arv, ach,
		func() string {
			if afmt == "" {
				return ""
			}
			return fmt.Sprintf("a=fmtp:%d %s\n", apt, afmt)
		}(),
		vPort, vpt,
		vpt, vpt, vfmt)
}

// startFFMPEG is called once both video & audio tracks are available.
func (r *Recorder) startFFMPEG() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.ffmpeg != nil {
		return nil // already started
	}

	// UDP sockets ---------------------------------------------------------
	var err error
	r.videoUDP, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.videoPort})
	if err != nil {
		return fmt.Errorf("video DialUDP: %w", err)
	}
	r.audioUDP, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: r.audioPort})
	if err != nil {
		return fmt.Errorf("audio DialUDP: %w", err)
	}

	// SDP ---------------------------------------------------------------
	sdp := generateUnifiedSDP(r.videoTrack, r.videoPort, r.audioTrack, r.audioPort)

	// ffmpeg -------------------------------------------------------------
	if err = os.MkdirAll(cfg.OutputDir, 0o775); err != nil {
		return err
	}
	segTemplate := filepath.Join(cfg.OutputDir, "%Y-%m-%d_%H-%M-%S.mp4")
	vf := `drawtext=` +
		`fontfile=/usr/share/DejaVuSansMono.ttf:` +
		`expansion=strftime:` +
		`text=%Y-%m-%d\ %H\\:%M\\:%S:` +
		`x=w-text_w-20:y=h-text_h-20:` +
		`fontsize=24:fontcolor=white:` +
		`shadowcolor=black:shadowx=2:shadowy=2:` +
		`box=1:boxcolor=black@0.4`

	ff := exec.Command("ffmpeg",
		"-loglevel", "warning",
		"-protocol_whitelist", "file,udp,rtp,pipe",
		"-fflags", "+genpts",
		"-f", "sdp", "-i", "pipe:0",
		"-vf", vf,
		"-c:v", "libx264", "-preset", "veryfast",
		"-c:a", "aac",
		"-movflags", "+faststart", "-reset_timestamps", "1",
		"-f", "segment", "-segment_time", fmt.Sprint(cfg.SegmentSeconds), "-strftime", "1",
		segTemplate,
	)
	stdin, _ := ff.StdinPipe()
	ff.Stderr = os.Stderr
	if err = ff.Start(); err != nil {
		return err
	}
	_, _ = io.WriteString(stdin, sdp)
	_ = stdin.Close()
	r.ffmpeg = ff
	log.Printf("[FFMPEG] started pid %d", ff.Process.Pid)
	time.Sleep(300 * time.Millisecond) // wait LISTEN

	// ---------------- RTP forwarding goroutines -------------------------
	go func() {
		for {
			pkt, _, err := r.videoTrack.ReadRTP()
			if err != nil {
				log.Println("[RTC] video ReadRTP:", err)
				return
			}
			raw, _ := pkt.Marshal()
			if _, err = r.videoUDP.Write(raw); err != nil {
				log.Println("[UDP] video write:", err)
				return
			}
		}
	}()

	go func() {
		for {
			pkt, _, err := r.audioTrack.ReadRTP()
			if err != nil {
				log.Println("[RTC] audio ReadRTP:", err)
				return
			}
			raw, _ := pkt.Marshal()
			if _, err = r.audioUDP.Write(raw); err != nil {
				log.Println("[UDP] audio write:", err)
				return
			}
		}
	}()

	return nil
}

func (r *Recorder) negotiate(ctx context.Context) error {
	// ---- WebRTC --------------------------------------------------------
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

	// m‑line と DataChannel
	_, _ = pc.AddTransceiverFromKind(
		webrtc.RTPCodecTypeAudio,
		webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly},
	)
	_, _ = pc.AddTransceiverFromKind(
		webrtc.RTPCodecTypeVideo,
		webrtc.RTPTransceiverInit{Direction: webrtc.RTPTransceiverDirectionRecvonly},
	)
	_, _ = pc.CreateDataChannel("data", nil)

	// ---- OnTrack -------------------------------------------------------
	pc.OnTrack(func(track *webrtc.TrackRemote, _ *webrtc.RTPReceiver) {
		log.Printf("[RTC] track arrived: %s pt=%d", track.Kind(), track.PayloadType())

		switch track.Kind() {
		case webrtc.RTPCodecTypeVideo:
			r.videoTrack = track
			if p, err := freeUDPPort(); err == nil {
				r.videoPort = p
			}
		case webrtc.RTPCodecTypeAudio:
			r.audioTrack = track
			if p, err := freeUDPPort(); err == nil {
				r.audioPort = p
			}
		}

		// 両方そろったら 1 回だけ起動
		if r.videoTrack != nil && r.audioTrack != nil {
			r.startOnce.Do(func() {
				go func() {
					if err := r.startFFMPEG(); err != nil {
						log.Println("[ERROR] startFFMPEG:", err)
					}
				}()
			})
		}
	})

	// ---- Offer / ICE complete -----------------------------------------
	offer, _ := pc.CreateOffer(nil)
	gather := webrtc.GatheringCompletePromise(pc)
	_ = pc.SetLocalDescription(offer)
	select {
	case <-gather:
	case <-time.After(5 * time.Second):
		return fmt.Errorf("ICE gathering timeout")
	}

	// ---- GenerateWebRtcStream -----------------------------------------
	type genResp struct {
		AnswerSDP    string `json:"answerSdp"`
		MediaSession string `json:"mediaSessionId"`
		ExpiresAt    string `json:"expiresAt"`
	}
	res, err := unmarshalCommand[genResp](
		ctx,
		"sdm.devices.commands.CameraLiveStream.GenerateWebRtcStream",
		map[string]any{"offerSdp": pc.LocalDescription().SDP},
	)
	if err != nil {
		return err
	}
	_ = pc.SetRemoteDescription(webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  res.AnswerSDP,
	})
	r.mediaSessionID = res.MediaSession
	r.streamExpires, _ = time.Parse(time.RFC3339, res.ExpiresAt)
	log.Printf("[RTC] stream valid until %s", r.streamExpires.Format(time.RFC3339))
	return nil
}

func (r *Recorder) extend(ctx context.Context) error {
	type extResp struct {
		AnswerSDP    string `json:"answerSdp"`
		MediaSession string `json:"mediaSessionId"`
		ExpiresAt    string `json:"expiresAt"`
	}
	res, err := unmarshalCommand[extResp](ctx,
		"sdm.devices.commands.CameraLiveStream.ExtendWebRtcStream",
		map[string]any{"mediaSessionId": r.mediaSessionID},
	)
	if err != nil {
		return err
	}
	r.mediaSessionID = res.MediaSession
	r.streamExpires, _ = time.Parse(time.RFC3339, res.ExpiresAt)
	log.Printf("[RTC] extended; valid until %s", r.streamExpires.Format(time.RFC3339))
	return nil
}

func (r *Recorder) close() {
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
		_ = r.ffmpeg.Wait()
	}
}

// ---------------------------------------------------------------------------
func main() {

	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("cannot read config: %v", err)
	}

	ctx := context.Background()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-sig:
			log.Println("Exiting by signal")
			return
		default:
		}

		rec := &Recorder{}
		if err := rec.negotiate(ctx); err != nil {
			log.Println("[ERROR] negotiate:", err)
			rec.close()
			time.Sleep(10 * time.Second)
			continue
		}

		for {
			wait := time.Until(rec.streamExpires.Add(
				-time.Duration(cfg.ExtendMarginSeconds) * time.Second))
			if wait > 0 {
				time.Sleep(wait)
			}

			select {
			case <-sig:
				log.Println("Exiting by signal")
				return
			default:
			}

			if err := rec.extend(ctx); err != nil {
				log.Println("[WARN] extend failed:", err, "→ renegotiate")
				rec.close()
				break
			}
		}
		rec.close()
		time.Sleep(10 * time.Second)
	}
}
