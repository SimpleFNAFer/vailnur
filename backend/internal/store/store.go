package store

import (
	"sync"
)

// JobStatus represents the lifecycle state of any job.
type JobStatus string

const (
	StatusPending JobStatus = "pending"
	StatusRunning JobStatus = "running"
	StatusDone    JobStatus = "done"
	StatusError   JobStatus = "error"
)

// Candidate is a crawled form/request with ML classification results.
type Candidate struct {
	ID          string              `json:"id"`
	Method      string              `json:"method"`
	URL         string              `json:"url"`
	Params      map[string][]string `json:"params"`
	Label       string              `json:"label"`
	Probability float64             `json:"probability"`
	BranchProbs map[string]float64  `json:"branch_probs"`
}

// ScanJob holds all state for a crawl + ML scan job.
type ScanJob struct {
	JobID        string      `json:"job_id"`
	Status       JobStatus   `json:"status"`
	TargetURL    string      `json:"target_url"`
	PagesCrawled int         `json:"pages_crawled"`
	Candidates   []Candidate `json:"candidates"`
	Error        string      `json:"error,omitempty"`
}

// ExploitResult is the outcome of sending one exploit request.
type ExploitResult struct {
	TargetID            string              `json:"target_id"`
	Method              string              `json:"method"`
	URL                 string              `json:"url"`
	Params              map[string][]string `json:"params"`
	StatusCode          int                 `json:"status_code"`
	ResponseExcerpt     string              `json:"response_excerpt"`
	ResponseSize        int64               `json:"response_size,omitempty"`
	ResponseContentType string              `json:"response_content_type,omitempty"`
	ResponseURL         string              `json:"response_url,omitempty"`
	ResponseFile        string              `json:"-"`
	Error               string              `json:"error,omitempty"`
}

// ExploitJob holds all state for an exploit job.
type ExploitJob struct {
	JobID   string          `json:"job_id"`
	Status  JobStatus       `json:"status"`
	Results []ExploitResult `json:"results"`
}

// Store is a thread-safe in-memory job store.
type Store struct {
	mu            sync.RWMutex
	scanJobs      map[string]*ScanJob
	exploitJobs   map[string]*ExploitJob
	responseFiles map[string]string // fileID -> tmp file path
}

// New creates an empty Store.
func New() *Store {
	return &Store{
		scanJobs:      make(map[string]*ScanJob),
		exploitJobs:   make(map[string]*ExploitJob),
		responseFiles: make(map[string]string),
	}
}

// SetScanJob upserts a ScanJob.
func (s *Store) SetScanJob(job *ScanJob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scanJobs[job.JobID] = job
}

// GetScanJob retrieves a ScanJob by ID; returns nil if not found.
func (s *Store) GetScanJob(id string) *ScanJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.scanJobs[id]
}

// SetExploitJob upserts an ExploitJob.
func (s *Store) SetExploitJob(job *ExploitJob) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.exploitJobs[job.JobID] = job
}

// GetExploitJob retrieves an ExploitJob by ID; returns nil if not found.
func (s *Store) GetExploitJob(id string) *ExploitJob {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.exploitJobs[id]
}

// SetResponseFile stores a mapping from a unique fileID to a tmp file path.
func (s *Store) SetResponseFile(fileID, path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.responseFiles[fileID] = path
}

// GetResponseFile returns the tmp file path for a given fileID.
func (s *Store) GetResponseFile(fileID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.responseFiles[fileID]
}
