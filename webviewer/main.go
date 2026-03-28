package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Recording struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

var (
	recordingsDir string
	indexTmpl     *template.Template
)

func init() {
	fm := template.FuncMap{
		"divMB": func(b int64) float64 { return float64(b) / (1024 * 1024) },
	}
	indexTmpl = template.Must(template.New("index").Funcs(fm).Parse(indexHTML))
}

func listRecordings() ([]Recording, error) {
	entries, err := os.ReadDir(recordingsDir)
	if err != nil {
		return nil, err
	}
	var recs []Recording
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".mp4") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		recs = append(recs, Recording{Name: name, Size: info.Size()})
	}
	// Sort newest first (filenames are timestamps)
	sort.Slice(recs, func(i, j int) bool {
		return recs[i].Name > recs[j].Name
	})
	return recs, nil
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	recs, err := listRecordings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	indexTmpl.Execute(w, recs)
}

func handleAPI(w http.ResponseWriter, r *http.Request) {
	recs, err := listRecordings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(recs)
}

func handleVideo(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Path[len("/video/"):]
	// Sanitize: only allow filenames, no path traversal
	name = filepath.Base(name)
	if !strings.HasSuffix(strings.ToLower(name), ".mp4") {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(recordingsDir, name)
	if _, err := os.Stat(path); os.IsNotExist(err) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "video/mp4")
	http.ServeFile(w, r, path)
}

func main() {
	dir := flag.String("dir", "../recordings", "path to recordings directory")
	addr := flag.String("addr", ":8080", "listen address")
	flag.Parse()

	absDir, err := filepath.Abs(*dir)
	if err != nil {
		log.Fatalf("invalid dir: %v", err)
	}
	recordingsDir = absDir
	log.Printf("Serving recordings from %s", recordingsDir)

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/api/recordings", handleAPI)
	http.HandleFunc("/video/", handleVideo)

	fmt.Printf("Web viewer running at http://localhost%s\n", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Nest Cam Recordings</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f0f; color: #e0e0e0; }
  header { background: #1a1a2e; padding: 16px 24px; border-bottom: 1px solid #333; }
  header h1 { font-size: 1.3rem; font-weight: 600; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px; }
  .player-section { margin-bottom: 32px; display: none; }
  .player-section.active { display: block; }
  .player-section h2 { font-size: 1rem; margin-bottom: 12px; color: #aaa; }
  .player-section .filename { color: #fff; font-weight: 600; }
  video { width: 100%; max-height: 70vh; background: #000; border-radius: 8px; }
  .recording-list { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; }
  .recording-item {
    background: #1a1a2e; border: 1px solid #2a2a3e; border-radius: 8px;
    padding: 16px; cursor: pointer; transition: background 0.15s, border-color 0.15s;
  }
  .recording-item:hover { background: #252540; border-color: #4a4a6e; }
  .recording-item.active { border-color: #6366f1; background: #1e1e3a; }
  .recording-item .name { font-size: 0.95rem; font-weight: 500; margin-bottom: 4px; }
  .recording-item .meta { font-size: 0.8rem; color: #888; }
  .empty { text-align: center; padding: 60px 20px; color: #666; }
</style>
</head>
<body>
<header><h1>Nest Cam Recordings</h1></header>
<div class="container">
  <div class="player-section" id="player-section">
    <h2>Now Playing: <span class="filename" id="now-playing"></span></h2>
    <video id="player" controls autoplay></video>
  </div>
  <div class="recording-list" id="list">
    {{if not .}}
    <div class="empty">No recordings found.</div>
    {{end}}
    {{range .}}
    <div class="recording-item" data-name="{{.Name}}" onclick="play(this)">
      <div class="name">{{.Name}}</div>
      <div class="meta">{{printf "%.1f" (divMB .Size)}} MB</div>
    </div>
    {{end}}
  </div>
</div>
<script>
function play(el) {
  document.querySelectorAll('.recording-item').forEach(e => e.classList.remove('active'));
  el.classList.add('active');
  var name = el.dataset.name;
  var player = document.getElementById('player');
  player.src = '/video/' + encodeURIComponent(name);
  document.getElementById('now-playing').textContent = name;
  document.getElementById('player-section').classList.add('active');
  player.play();
}
</script>
</body>
</html>
`
