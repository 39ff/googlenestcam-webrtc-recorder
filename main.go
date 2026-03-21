package main

import (
	"context"
	"flag"
	"log"
	"net/http"
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

	// Signal-aware context so Negotiate() and other blocking calls
	// are interrupted on SIGINT/SIGTERM.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	for {
		select {
		case <-ctx.Done():
			log.Println("Exiting by signal")
			return
		default:
		}

		rec := NewRecorder(ctx, cfg, sdm)
		if err := rec.Negotiate(rec.ctx); err != nil {
			if ctx.Err() != nil {
				log.Println("Exiting by signal")
				rec.Close()
				return
			}
			log.Println("[ERROR] negotiate:", err)
			rec.Close()
			time.Sleep(10 * time.Second)
			continue
		}

		if exited := runExtendLoop(rec, ctx); exited {
			return
		}
		time.Sleep(10 * time.Second)
	}
}

// runExtendLoop monitors the recording session, extending it before expiry
// and restarting on errors or signals. Returns true if the program should exit.
func runExtendLoop(rec *Recorder, ctx context.Context) bool {
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
					return false
				}
				continue
			case <-ctx.Done():
				log.Println("Exiting by signal")
				rec.Close()
				return true
			case rtpErr := <-rec.errorChan:
				log.Printf("[ERROR] RTP stream failed: %v -> renegotiate", rtpErr)
				rec.Close()
				return false
			}
		}

		select {
		case <-ctx.Done():
			log.Println("Exiting by signal")
			rec.Close()
			return true
		case rtpErr := <-rec.errorChan:
			log.Printf("[ERROR] RTP stream failed: %v -> renegotiate", rtpErr)
			rec.Close()
			return false
		case <-time.After(wait):
			// Time to extend
		}
	}
}
