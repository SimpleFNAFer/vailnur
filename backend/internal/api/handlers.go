package api

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/SimpleFNAFer/dplm/backend/internal/crawler"
	"github.com/SimpleFNAFer/dplm/backend/internal/exploit"
	"github.com/SimpleFNAFer/dplm/backend/internal/mlclient"
	"github.com/SimpleFNAFer/dplm/backend/internal/store"
)

// Handler bundles all dependencies for the HTTP handlers.
type Handler struct {
	store    *store.Store
	mlClient *mlclient.Client
}

// NewRouter creates the chi router with all routes and CORS middleware.
func NewRouter(s *store.Store, ml *mlclient.Client) http.Handler {
	h := &Handler{store: s, mlClient: ml}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(corsMiddleware)

	r.Post("/api/scan", h.postScan)
	r.Get("/api/scan/{id}", h.getScan)
	r.Post("/api/exploit", h.postExploit)
	r.Get("/api/exploit/{id}", h.getExploit)
	r.Get("/api/exploit/response/{id}", h.getExploitResponse)
	r.Get("/api/report", h.getReport)

	return r
}

// corsMiddleware allows all origins with JSON content type.
func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// --- POST /api/scan ---

type scanRequest struct {
	URL      string `json:"url"`
	Depth    *int   `json:"depth"`
	MaxPages *int   `json:"max_pages"`
}

func (h *Handler) postScan(w http.ResponseWriter, r *http.Request) {
	var req scanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.URL == "" {
		jsonError(w, "url is required", http.StatusBadRequest)
		return
	}

	depth := 2
	if req.Depth != nil {
		depth = *req.Depth
	}
	maxPages := 50
	if req.MaxPages != nil {
		maxPages = *req.MaxPages
	}

	jobID := uuid.NewString()
	job := &store.ScanJob{
		JobID:      jobID,
		Status:     store.StatusPending,
		TargetURL:  req.URL,
		Candidates: []store.Candidate{},
	}
	h.store.SetScanJob(job)

	go h.runScan(jobID, req.URL, depth, maxPages)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID}) //nolint:errcheck
}

func (h *Handler) runScan(jobID, targetURL string, depth, maxPages int) {
	// Mark running
	job := h.store.GetScanJob(jobID)
	job.Status = store.StatusRunning
	h.store.SetScanJob(job)

	c := &crawler.Crawler{MaxDepth: depth, MaxPages: maxPages}
	rawReqs, pagesCrawled, err := c.Crawl(targetURL)
	crawledReqs := deduplicateRequests(rawReqs)
	if err != nil {
		job.Status = store.StatusError
		job.Error = err.Error()
		h.store.SetScanJob(job)
		return
	}

	job.PagesCrawled = pagesCrawled
	h.store.SetScanJob(job)

	if len(crawledReqs) == 0 {
		job.Status = store.StatusDone
		h.store.SetScanJob(job)
		return
	}

	// Build ML batch
	mlReqs := make([]mlclient.PredictRequest, len(crawledReqs))
	for i, cr := range crawledReqs {
		mlReqs[i] = mlclient.PredictRequest{
			Method: cr.Method,
			URL:    cr.URL,
			Params: cr.Params,
		}
	}

	results, err := h.mlClient.PredictBatch(mlReqs)
	if err != nil {
		job.Status = store.StatusError
		job.Error = err.Error()
		h.store.SetScanJob(job)
		return
	}

	// Store only CSRF candidates
	var candidates []store.Candidate
	for i, res := range results {
		if res.Label != "csrf" {
			continue
		}
		candidates = append(candidates, store.Candidate{
			ID:          uuid.NewString(),
			Method:      crawledReqs[i].Method,
			URL:         crawledReqs[i].URL,
			Params:      crawledReqs[i].Params,
			Label:       res.Label,
			Probability: res.Probability,
			BranchProbs: res.BranchProbs,
		})
	}
	if candidates == nil {
		candidates = []store.Candidate{}
	}

	job.Candidates = candidates
	job.Status = store.StatusDone
	h.store.SetScanJob(job)
}

// --- GET /api/scan/{id} ---

func (h *Handler) getScan(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	job := h.store.GetScanJob(id)
	if job == nil {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}
	jsonOK(w, job)
}

// --- POST /api/exploit ---

type exploitTarget struct {
	ID     string              `json:"id"`
	Method string              `json:"method"`
	URL    string              `json:"url"`
	Params map[string][]string `json:"params"`
}

type exploitRequest struct {
	Targets []exploitTarget `json:"targets"`
}

func (h *Handler) postExploit(w http.ResponseWriter, r *http.Request) {
	var req exploitRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if len(req.Targets) == 0 {
		jsonError(w, "targets is required and must not be empty", http.StatusBadRequest)
		return
	}

	jobID := uuid.NewString()
	job := &store.ExploitJob{
		JobID:   jobID,
		Status:  store.StatusPending,
		Results: []store.ExploitResult{},
	}
	h.store.SetExploitJob(job)

	go h.runExploit(jobID, req.Targets)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]string{"job_id": jobID}) //nolint:errcheck
}

func (h *Handler) runExploit(jobID string, targets []exploitTarget) {
	job := h.store.GetExploitJob(jobID)
	job.Status = store.StatusRunning
	h.store.SetExploitJob(job)

	runner := exploit.New()
	results := make([]store.ExploitResult, 0, len(targets))

	for _, t := range targets {
		params := t.Params
		if params == nil {
			params = map[string][]string{}
		}
		res := runner.Execute(exploit.Target{
			ID:     t.ID,
			Method: t.Method,
			URL:    t.URL,
			Params: params,
		})

		er := store.ExploitResult{
			TargetID:            res.TargetID,
			Method:              t.Method,
			URL:                 t.URL,
			Params:              params,
			StatusCode:          res.StatusCode,
			ResponseExcerpt:     res.ResponseExcerpt,
			ResponseSize:        res.ResponseSize,
			ResponseContentType: res.ContentType,
		}
		if res.ResponseFile != "" {
			fileID := uuid.NewString()
			h.store.SetResponseFile(fileID, res.ResponseFile)
			er.ResponseURL = "/api/exploit/response/" + fileID
		}
		if res.Err != nil {
			er.Error = res.Err.Error()
		}
		results = append(results, er)
	}

	job.Results = results
	job.Status = store.StatusDone
	h.store.SetExploitJob(job)
}

// --- GET /api/exploit/{id} ---

func (h *Handler) getExploit(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	job := h.store.GetExploitJob(id)
	if job == nil {
		jsonError(w, "job not found", http.StatusNotFound)
		return
	}
	jsonOK(w, job)
}

// --- GET /api/exploit/response/{id} ---

func (h *Handler) getExploitResponse(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	path := h.store.GetResponseFile(id)
	if path == "" {
		jsonError(w, "response file not found", http.StatusNotFound)
		return
	}
	if _, err := os.Stat(path); err != nil {
		jsonError(w, "response file not found on disk", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="response.bin"`)
	http.ServeFile(w, r, path)
}

// --- GET /api/report ---

type reportResultJSON struct {
	TargetID            string              `json:"target_id"`
	Method              string              `json:"method"`
	URL                 string              `json:"url"`
	Params              map[string][]string `json:"params"`
	StatusCode          int                 `json:"status_code"`
	ResponseExcerpt     string              `json:"response_excerpt"`
	ResponseSize        int64               `json:"response_size,omitempty"`
	ResponseContentType string              `json:"response_content_type,omitempty"`
	ResponsePath        string              `json:"response_path,omitempty"`
	Error               string              `json:"error,omitempty"`
}

type reportJSON struct {
	ReportDate string `json:"report_date"`
	Scan       *struct {
		TargetURL    string            `json:"target_url"`
		PagesCrawled int               `json:"pages_crawled"`
		Candidates   []store.Candidate `json:"candidates"`
	} `json:"scan,omitempty"`
	Exploit *struct {
		Results []reportResultJSON `json:"results"`
	} `json:"exploit,omitempty"`
}

func (h *Handler) getReport(w http.ResponseWriter, r *http.Request) {
	scanID := r.URL.Query().Get("scan_id")
	exploitID := r.URL.Query().Get("exploit_id")

	if scanID == "" && exploitID == "" {
		jsonError(w, "scan_id or exploit_id required", http.StatusBadRequest)
		return
	}

	var scanJob *store.ScanJob
	if scanID != "" {
		scanJob = h.store.GetScanJob(scanID)
		if scanJob == nil {
			jsonError(w, "scan job not found", http.StatusNotFound)
			return
		}
	}

	var exploitJob *store.ExploitJob
	if exploitID != "" {
		exploitJob = h.store.GetExploitJob(exploitID)
		if exploitJob == nil {
			jsonError(w, "exploit job not found", http.StatusNotFound)
			return
		}
	}

	rep := reportJSON{ReportDate: time.Now().UTC().Format(time.RFC3339)}

	if scanJob != nil {
		rep.Scan = &struct {
			TargetURL    string            `json:"target_url"`
			PagesCrawled int               `json:"pages_crawled"`
			Candidates   []store.Candidate `json:"candidates"`
		}{
			TargetURL:    scanJob.TargetURL,
			PagesCrawled: scanJob.PagesCrawled,
			Candidates:   scanJob.Candidates,
		}
	}

	type fileEntry struct{ zipName, diskPath string }
	var files []fileEntry

	if exploitJob != nil {
		results := make([]reportResultJSON, len(exploitJob.Results))
		for i, er := range exploitJob.Results {
			rr := reportResultJSON{
				TargetID:            er.TargetID,
				Method:              er.Method,
				URL:                 er.URL,
				Params:              er.Params,
				StatusCode:          er.StatusCode,
				ResponseExcerpt:     er.ResponseExcerpt,
				ResponseSize:        er.ResponseSize,
				ResponseContentType: er.ResponseContentType,
				Error:               er.Error,
			}
			if er.ResponseURL != "" {
				parts := strings.Split(er.ResponseURL, "/")
				fileID := parts[len(parts)-1]
				diskPath := h.store.GetResponseFile(fileID)
				if diskPath != "" {
					zipName := "responses/" + fileID + ".bin"
					rr.ResponsePath = zipName
					files = append(files, fileEntry{zipName, diskPath})
				}
			}
			results[i] = rr
		}
		rep.Exploit = &struct {
			Results []reportResultJSON `json:"results"`
		}{Results: results}
	}

	reportBytes, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		jsonError(w, "failed to marshal report", http.StatusInternalServerError)
		return
	}

	ts := time.Now().UTC().Format("2006-01-02T15-04-05")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="csrf-report-%s.zip"`, ts))

	zw := zip.NewWriter(w)
	defer zw.Close() //nolint:errcheck

	jf, err := zw.Create("report.json")
	if err == nil {
		jf.Write(reportBytes) //nolint:errcheck
	}

	for _, fe := range files {
		f, err := os.Open(fe.diskPath)
		if err != nil {
			continue
		}
		zf, err := zw.Create(fe.zipName)
		if err != nil {
			f.Close()
			continue
		}
		io.Copy(zf, f) //nolint:errcheck
		f.Close()
	}
}

// deduplicateRequests removes requests with identical method+url+params.
func deduplicateRequests(reqs []crawler.Request) []crawler.Request {
	seen := make(map[string]bool, len(reqs))
	out := make([]crawler.Request, 0, len(reqs))
	for _, r := range reqs {
		key := requestKey(r)
		if !seen[key] {
			seen[key] = true
			out = append(out, r)
		}
	}
	return out
}

func requestKey(r crawler.Request) string {
	keys := make([]string, 0, len(r.Params))
	for k := range r.Params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vals := append([]string(nil), r.Params[k]...)
		sort.Strings(vals)
		parts = append(parts, fmt.Sprintf("%s=%s", k, strings.Join(vals, ",")))
	}
	return r.Method + "|" + r.URL + "|" + strings.Join(parts, "&")
}

// --- helpers ---

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}
