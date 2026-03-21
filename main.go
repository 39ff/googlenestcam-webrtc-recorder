package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	cfgPath := flag.String("config", "config.yaml", "path to config file")
	flag.Parse()

	cfg, err := LoadConfig(*cfgPath)
	if err != nil {
		log.Fatalf("cannot read config: %v", err)
	}

	httpClient := &http.Client{Timeout: 20 * time.Second}
	auth := NewAuthClient(cfg, httpClient)
	sdm := NewSDMClient(auth, httpClient, cfg.DeviceID)

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

		rec := NewRecorder(ctx, cfg, sdm)
		if err := rec.Negotiate(rec.ctx); err != nil {
			log.Println("[ERROR] negotiate:", err)
			rec.Close()
			time.Sleep(10 * time.Second)
			continue
		}

		runExtendLoop(rec, sig)
		time.Sleep(10 * time.Second)
	}
}

// runExtendLoop monitors the recording session, extending it before expiry
// and restarting on errors or signals.
func runExtendLoop(rec *Recorder, sig chan os.Signal) {
	margin := time.Duration(rec.cfg.ExtendMarginSeconds) * time.Second

	for {
		wait := time.Until(rec.streamExpires.Add(-margin))

		if wait <= 0 {
			extendErr := make(chan error, 1)
			go func() {
				extendErr <- rec.Extend(rec.ctx)
			}()
			select {
			case err := <-extendErr:
				if err != nil {
					log.Println("[WARN] extend failed:", err, "-> renegotiate")
					rec.Close()
					return
				}
				continue
			case <-sig:
				log.Println("Exiting by signal")
				rec.Close()
				os.Exit(0)
			case rtpErr := <-rec.errorChan:
				log.Printf("[ERROR] RTP stream failed: %v -> renegotiate", rtpErr)
				rec.Close()
				return
			}
		}

		select {
		case <-sig:
			log.Println("Exiting by signal")
			rec.Close()
			os.Exit(0)
		case rtpErr := <-rec.errorChan:
			log.Printf("[ERROR] RTP stream failed: %v -> renegotiate", rtpErr)
			rec.Close()
			return
		case <-time.After(wait):
			// Time to extend
		}
	}
}
