# googlenestcam-webrtc-recorder
Nest Cam WebRTC Recorder (Google Device Access API)

**Continuous, reliable recording of Google Nest Cam video & audio over WebRTC, saved as rolling `.mp4` segments.**  
Written in Go 1.22 + FFmpeg. Runs anywhere – bare-metal, Docker, or Docker Compose.

<p align="center">
  <img src="https://raw.githubusercontent.com/39ff/googlenestcam-webrtc-recorder/refs/heads/demo/sample_cam.png" width="700" alt="demo recording">
</p>

```
cp config-sample.yaml config.yaml
vi config.yaml
docker compose up -d
```


```
ls ./recordings/
2025-05-17_18-07-59.mp4
```

### Disclaimer
All of this code was generated using ChatGPT o3(2025-05).
Please use it at your own risk.

### LICENSE
```
- googlenestcam-webrtc-recorder
Apache License 2.0


- DejaVu Sans Mono Fonts
Copyright (c) 2003 by Bitstream, Inc. All Rights Reserved.
DejaVu changes are in public domain

```


If you need more advanced motion detection or similar capabilities, check out the following open-source project:

https://github.com/blakeblackshear/frigate