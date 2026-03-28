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
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0f0f0f; color: #e0e0e0; height: 100vh; overflow: hidden; }

  .layout { display: flex; height: 100vh; }

  /* --- Sidebar --- */
  .sidebar {
    width: 280px; min-width: 220px; max-width: 360px;
    background: #1a1a2e; border-right: 1px solid #333;
    display: flex; flex-direction: column; flex-shrink: 0;
  }
  .sidebar-header {
    padding: 16px; border-bottom: 1px solid #333;
    font-size: 1.1rem; font-weight: 600;
  }
  .sidebar-filter {
    padding: 8px 12px; border-bottom: 1px solid #2a2a3e;
  }
  .sidebar-filter input {
    width: 100%; padding: 6px 10px; border-radius: 4px;
    border: 1px solid #333; background: #12121e; color: #e0e0e0;
    font-size: 0.85rem; outline: none;
  }
  .sidebar-filter input:focus { border-color: #6366f1; }
  .file-list {
    flex: 1; overflow-y: auto; padding: 4px 0;
  }
  .file-list::-webkit-scrollbar { width: 6px; }
  .file-list::-webkit-scrollbar-thumb { background: #444; border-radius: 3px; }
  .file-item {
    display: flex; justify-content: space-between; align-items: center;
    padding: 10px 16px; cursor: pointer;
    border-left: 3px solid transparent;
    transition: background 0.12s, border-color 0.12s;
    font-size: 0.85rem;
  }
  .file-item:hover { background: #252540; }
  .file-item.active { background: #1e1e3a; border-left-color: #6366f1; }
  .file-item .fname { white-space: nowrap; overflow: hidden; text-overflow: ellipsis; flex: 1; }
  .file-item .fsize { color: #666; font-size: 0.75rem; margin-left: 8px; flex-shrink: 0; }
  .file-count { padding: 10px 16px; font-size: 0.75rem; color: #555; border-top: 1px solid #2a2a3e; }

  /* --- Main content --- */
  .main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
  .main-header {
    padding: 12px 24px; border-bottom: 1px solid #333; background: #141420;
    font-size: 0.9rem; color: #888; min-height: 46px; display: flex; align-items: center;
  }
  .main-header .filename { color: #fff; font-weight: 600; margin-left: 6px; }
  .player-wrap {
    flex: 1; display: flex; align-items: center; justify-content: center;
    background: #000; padding: 16px; overflow: hidden;
  }
  video { max-width: 100%; max-height: 100%; border-radius: 4px; background: #000; }
  .placeholder {
    color: #444; font-size: 1.1rem; text-align: center;
  }
</style>
</head>
<body>
<div class="layout">
  <!-- Sidebar -->
  <div class="sidebar">
    <div class="sidebar-header">Recordings</div>
    <div class="sidebar-filter">
      <input type="text" id="filter" placeholder="Filter..." oninput="filterList()">
    </div>
    <div class="file-list" id="file-list">
      {{if not .}}<div style="padding:40px 16px;color:#555;text-align:center">No recordings found.</div>{{end}}
      {{range .}}
      <div class="file-item" data-name="{{.Name}}" onclick="play(this)">
        <span class="fname">{{.Name}}</span>
        <span class="fsize">{{printf "%.1f" (divMB .Size)}} MB</span>
      </div>
      {{end}}
    </div>
    <div class="file-count" id="file-count"></div>
  </div>

  <!-- Main -->
  <div class="main">
    <div class="main-header">
      <span id="now-playing-label" style="display:none">Now Playing:</span>
      <span class="filename" id="now-playing"></span>
    </div>
    <div class="player-wrap">
      <div class="placeholder" id="placeholder">Select a recording to play</div>
      <video id="player" controls style="display:none"></video>
    </div>
  </div>
</div>

<script>
var allItems = document.querySelectorAll('.file-item');
updateCount(allItems.length);

function updateCount(visible) {
  document.getElementById('file-count').textContent = visible + ' / ' + allItems.length + ' files';
}

function filterList() {
  var q = document.getElementById('filter').value.toLowerCase();
  var visible = 0;
  allItems.forEach(function(el) {
    var match = el.dataset.name.toLowerCase().indexOf(q) !== -1;
    el.style.display = match ? '' : 'none';
    if (match) visible++;
  });
  updateCount(visible);
}

function play(el) {
  allItems.forEach(function(e) { e.classList.remove('active'); });
  el.classList.add('active');
  var name = el.dataset.name;
  var player = document.getElementById('player');
  player.src = '/video/' + encodeURIComponent(name);
  player.style.display = '';
  document.getElementById('placeholder').style.display = 'none';
  document.getElementById('now-playing').textContent = name;
  document.getElementById('now-playing-label').style.display = '';
  player.play();
}

// Keyboard: arrow up/down to navigate, Enter to play
document.addEventListener('keydown', function(e) {
  if (e.target.tagName === 'INPUT') return;
  var items = Array.from(allItems).filter(function(el) { return el.style.display !== 'none'; });
  if (!items.length) return;
  var idx = items.findIndex(function(el) { return el.classList.contains('active'); });
  if (e.key === 'ArrowDown') { e.preventDefault(); play(items[Math.min(idx + 1, items.length - 1)]); items[Math.min(idx + 1, items.length - 1)].scrollIntoView({block:'nearest'}); }
  if (e.key === 'ArrowUp')   { e.preventDefault(); play(items[Math.max(idx - 1, 0)]); items[Math.max(idx - 1, 0)].scrollIntoView({block:'nearest'}); }
});
</script>
</body>
</html>
`
