package schedule

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Job struct {
	Name     string              `json:"name"`
	Target   string              `json:"target"`
	Profile  string              `json:"profile"`
	Schedule CronSchedule        `json:"schedule"`
	LastRun  time.Time           `json:"last_run"`
	NextRun  time.Time           `json:"next_run"`
	Enabled  bool                `json:"enabled"`
	RunFunc  func(job Job) error `json:"-"`
}

type CronSchedule struct {
	Minute     string `json:"minute"`
	Hour       string `json:"hour"`
	DayOfMonth string `json:"day_of_month"`
	Month      string `json:"month"`
	DayOfWeek  string `json:"day_of_week"`
}

type Scheduler struct {
	mu       sync.RWMutex
	jobs     map[string]*Job
	running  bool
	stopCh   chan struct{}
	tickRate time.Duration
}

func NewScheduler() *Scheduler {
	return &Scheduler{
		jobs:     make(map[string]*Job),
		stopCh:   make(chan struct{}),
		tickRate: 30 * time.Second,
	}
}

func (s *Scheduler) AddJob(job Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	job.NextRun = NextRunTime(job.Schedule)
	s.jobs[job.Name] = &job
}

func (s *Scheduler) RemoveJob(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.jobs, name)
}

func (s *Scheduler) ListJobs() []Job {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jobs := make([]Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		jobs = append(jobs, *j)
	}
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].NextRun.Before(jobs[j].NextRun)
	})
	return jobs
}

func (s *Scheduler) RunJob(name string) error {
	s.mu.RLock()
	job, ok := s.jobs[name]
	s.mu.RUnlock()
	if !ok {
		return fmt.Errorf("job not found: %s", name)
	}
	if job.RunFunc == nil {
		return fmt.Errorf("no run function for job: %s", name)
	}
	job.LastRun = time.Now()
	job.NextRun = NextRunTime(job.Schedule)
	return job.RunFunc(*job)
}

func (s *Scheduler) Start() {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	s.running = true
	s.mu.Unlock()

	go func() {
		ticker := time.NewTicker(s.tickRate)
		defer ticker.Stop()
		for {
			select {
			case <-s.stopCh:
				return
			case <-ticker.C:
				s.tick()
			}
		}
	}()
}

func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.running {
		return
	}
	close(s.stopCh)
	s.running = false
}

func (s *Scheduler) tick() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	for _, job := range s.jobs {
		if !job.Enabled {
			continue
		}
		if now.After(job.NextRun) || now.Equal(job.NextRun) {
			if job.RunFunc != nil {
				go func(j *Job) {
					j.LastRun = time.Now()
					j.NextRun = NextRunTime(j.Schedule)
					j.RunFunc(*j)
				}(job)
			} else {
				job.LastRun = now
				job.NextRun = NextRunTime(job.Schedule)
			}
		}
	}
}

func (s *Scheduler) SaveJobs(path string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jobs := make([]Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		jobs = append(jobs, *j)
	}
	sort.Slice(jobs, func(i, j int) bool {
		return jobs[i].Name < jobs[j].Name
	})

	data, err := json.MarshalIndent(jobs, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal jobs: %w", err)
	}
	return os.WriteFile(path, data, 0644)
}

func (s *Scheduler) LoadJobs(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read jobs: %w", err)
	}

	var jobs []Job
	if err := json.Unmarshal(data, &jobs); err != nil {
		return fmt.Errorf("unmarshal jobs: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range jobs {
		jobs[i].NextRun = NextRunTime(jobs[i].Schedule)
		s.jobs[jobs[i].Name] = &jobs[i]
	}
	return nil
}

func ParseCron(expr string) CronSchedule {
	fields := strings.Fields(expr)
	schedule := CronSchedule{}
	if len(fields) >= 1 {
		schedule.Minute = fields[0]
	}
	if len(fields) >= 2 {
		schedule.Hour = fields[1]
	}
	if len(fields) >= 3 {
		schedule.DayOfMonth = fields[2]
	}
	if len(fields) >= 4 {
		schedule.Month = fields[3]
	}
	if len(fields) >= 5 {
		schedule.DayOfWeek = fields[4]
	}
	return schedule
}

func NextRunTime(schedule CronSchedule) time.Time {
	now := time.Now()
	next := now.Add(time.Minute)

	for i := 0; i < 366*24*60; i++ {
		if matchesSchedule(next, schedule) {
			return next
		}
		next = next.Add(time.Minute)
	}
	return now.Add(24 * time.Hour)
}

func matchesSchedule(t time.Time, schedule CronSchedule) bool {
	if !matchField(schedule.Minute, t.Minute()) {
		return false
	}
	if !matchField(schedule.Hour, t.Hour()) {
		return false
	}
	if !matchField(schedule.DayOfMonth, t.Day()) {
		return false
	}
	if !matchField(schedule.Month, int(t.Month())) {
		return false
	}
	if !matchField(schedule.DayOfWeek, int(t.Weekday())) {
		return false
	}
	return true
}

func matchField(field string, value int) bool {
	if field == "" || field == "*" {
		return true
	}

	if strings.Contains(field, ",") {
		for _, part := range strings.Split(field, ",") {
			if matchSingleField(part, value) {
				return true
			}
		}
		return false
	}

	if strings.Contains(field, "/") {
		parts := strings.Split(field, "/")
		if len(parts) != 2 {
			return false
		}
		step, err := strconv.Atoi(parts[1])
		if err != nil || step <= 0 {
			return false
		}
		if parts[0] == "*" {
			return value%step == 0
		}
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return false
		}
		return value >= start && value%step == 0
	}

	if strings.Contains(field, "-") {
		parts := strings.Split(field, "-")
		if len(parts) != 2 {
			return false
		}
		start, err := strconv.Atoi(parts[0])
		if err != nil {
			return false
		}
		end, err := strconv.Atoi(parts[1])
		if err != nil {
			return false
		}
		return value >= start && value <= end
	}

	return matchSingleField(field, value)
}

func matchSingleField(field string, value int) bool {
	field = strings.TrimSpace(field)
	if field == "*" {
		return true
	}
	n, err := strconv.Atoi(field)
	if err != nil {
		return false
	}
	return n == value
}
