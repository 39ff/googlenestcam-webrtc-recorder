package main

import (
	"fmt"
	"strings"

	"github.com/pion/webrtc/v4"
)

// generateUnifiedSDP builds an SDP describing "video + audio" streams
// for ffmpeg to consume via RTP.
func generateUnifiedSDP(v *webrtc.TrackRemote, vPort int,
	a *webrtc.TrackRemote, aPort int) string {

	vpt := v.PayloadType()
	vfmt := v.Codec().SDPFmtpLine
	if !strings.Contains(vfmt, "packetization-mode") {
		vfmt = "packetization-mode=1; " + vfmt
	}

	apt := a.PayloadType()
	acodec := strings.ToUpper(strings.Split(a.Codec().MimeType, "/")[1])
	ach := a.Codec().Channels
	arv := a.Codec().ClockRate
	afmt := a.Codec().SDPFmtpLine

	var afmtLine string
	if afmt != "" {
		afmtLine = fmt.Sprintf("a=fmtp:%d %s\n", apt, afmt)
	}

	return fmt.Sprintf(`v=0
o=- 0 0 IN IP4 127.0.0.1
s=NestCam
c=IN IP4 127.0.0.1
t=0 0
m=audio %d RTP/AVP %d
a=rtpmap:%d %s/%d/%d
%sm=video %d RTP/AVP %d
a=rtpmap:%d H264/90000
a=fmtp:%d %s
`, aPort, apt,
		apt, acodec, arv, ach,
		afmtLine,
		vPort, vpt,
		vpt, vpt, vfmt)
}
