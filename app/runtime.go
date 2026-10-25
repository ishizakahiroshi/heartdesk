// Package app assembles the standard monitor and scheduler for embedding.
// The existing stores and registries are process scoped: one Runtime may be
// initialized during a process lifetime. Close does not permit reinitialization.
package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ishizakahiroshi/heartdesk/core/monitor"
	heartdesk "github.com/ishizakahiroshi/heartdesk/internal"
	"github.com/ishizakahiroshi/heartdesk/internal/alerts"
	"github.com/ishizakahiroshi/heartdesk/internal/auditdb"
	"github.com/ishizakahiroshi/heartdesk/internal/auth"
	"github.com/ishizakahiroshi/heartdesk/internal/authz"
	"github.com/ishizakahiroshi/heartdesk/internal/config"
	"github.com/ishizakahiroshi/heartdesk/internal/license"
	"github.com/ishizakahiroshi/heartdesk/internal/routing"
	"github.com/ishizakahiroshi/heartdesk/internal/scheduler"
)

type Config = config.AppConfig
type SchedulerConfig = config.SchedulerConfig
type RoutingConfig = routing.Config
type Session = auth.Session
type Job = scheduler.JobDef
type AgentConfig = config.AgentConfig
type SigningKeyEntry = config.SigningKeyEntry
type CardsConfig = config.CardsConfig
type SystemInfoData = config.SystemInfoData
type Notifier = alerts.Notifier
type DeliveryResult = alerts.DeliveryResult
type LicenseConfig = license.Config
type AuthIdentityConfig = auth.IdentityConfig
type OperationalIdentityConfig = heartdesk.OperationalIdentityConfig
type MonitorIdentityConfig = monitor.MonitorIdentityConfig

// Options supplies explicit application identity and paths. Environment is a
// snapshot of internal configuration keys; it never changes the process env.
// Config and Environment are copied. ConfigLoader is called for tenant cache
// misses and must return a fresh, immutable configuration for the requested ID.
type Options struct {
	BaseDir, ConfigDir, DataDir, TenantID, DefaultTenantID          string
	SelfServiceName, ExtractJobID                                   string
	SessionCookieName, CSRFCookieName, Brand, Version, AssetVersion string
	Environment                                                     map[string]string
	ActionPermissionAliases                                         map[string]string
	CardAliases                                                     map[string]string
	VendorName                                                      string
	Config                                                          *Config
	ConfigLoader                                                    func(string) (*Config, error)
	Routing                                                         *RoutingConfig
	SchedulerConfig                                                 *SchedulerConfig
	SchedulerOnly                                                   bool
	TemplateFS, StaticFS                                            fs.FS
	VerifyLicense                                                   func(*Config) error
	LicenseConfig                                                   *LicenseConfig
	AuthIdentity                                                    *AuthIdentityConfig
	OperationalIdentity                                             *OperationalIdentityConfig
	MonitorIdentity                                                 *MonitorIdentityConfig
	SkipStartupMaintenance                                          bool
	Jobs                                                            []Job
	Extensions                                                      Extensions
	Routes                                                          []Route
	Notifiers                                                       []Notifier
	OnReportSaved                                                   func(*RequestContext, AgentReport)
}

var ErrRuntimeInitialized = errors.New("app: a runtime has already been initialized in this process")
var runtimeGate struct {
	sync.Mutex
	initialized bool
}

type Runtime struct {
	opts                             Options
	config                           *Config
	routes                           RoutingConfig
	monitor                          *monitor.Handler
	handler                          http.Handler
	addr                             string
	reportDB                         *sql.DB
	ownedDB                          *sql.DB
	ownedAuditDB                     bool
	ctx                              context.Context
	cancel                           context.CancelFunc
	closed                           atomic.Bool
	closeOnce                        sync.Once
	closeErr                         error
	lifecycleMu                      sync.Mutex
	workers                          sync.WaitGroup
	monitorStarted, schedulerStarted bool
	startupOnce                      sync.Once
	startupErr                       error
	prepared                         atomic.Bool
	maintenanceOnce                  sync.Once
}

func OptionsFromEnvironment() Options {
	return Options{BaseDir: os.Getenv("HEARTDESK_BASE_DIR"), ConfigDir: os.Getenv("HEARTDESK_CONFIG_DIR"), DataDir: os.Getenv("HEARTDESK_DATA_DIR"), TenantID: os.Getenv("HEARTDESK_TENANT_ID")}
}

// LoadConfig uses the normal base/secrets/tenant/agent overlay order at dir.
func LoadConfig(dir, tenantID string) (*Config, error) {
	return config.LoadAppConfigForTenantAt(dir, tenantID)
}

func New(options Options) (*Runtime, error) {
	runtimeGate.Lock()
	defer runtimeGate.Unlock()
	if runtimeGate.initialized {
		return nil, ErrRuntimeInitialized
	}
	opts := options
	opts.Environment = map[string]string{}
	for k, v := range options.Environment {
		opts.Environment[k] = v
	}
	opts.ActionPermissionAliases = map[string]string{}
	for key, target := range options.ActionPermissionAliases {
		opts.ActionPermissionAliases[key] = target
	}
	if err := authz.ValidateActionPermissionAliases(opts.ActionPermissionAliases); err != nil {
		return nil, err
	}
	opts.CardAliases = map[string]string{}
	for key, target := range options.CardAliases {
		opts.CardAliases[key] = target
	}
	if err := authz.ValidateCardAliases(opts.CardAliases); err != nil {
		return nil, err
	}
	if err := validateCardAliasTargets(opts.CardAliases, opts.Extensions); err != nil {
		return nil, err
	}
	if opts.OperationalIdentity != nil {
		copy := *opts.OperationalIdentity
		opts.OperationalIdentity = &copy
	}
	if err := heartdesk.ValidateOperationalIdentity(opts.OperationalIdentity); err != nil {
		return nil, err
	}
	if opts.MonitorIdentity != nil {
		copy := *opts.MonitorIdentity
		opts.MonitorIdentity = &copy
	}
	if err := monitor.ValidateMonitorIdentity(opts.MonitorIdentity); err != nil {
		return nil, err
	}
	identity := AuthIdentityConfig{}
	if opts.AuthIdentity != nil {
		identity = *opts.AuthIdentity
	}
	if err := auth.ValidateIdentity(identity); err != nil {
		return nil, err
	}
	opts.AuthIdentity = &identity
	if opts.BaseDir == "" {
		opts.BaseDir = opts.Environment["HEARTDESK_BASE_DIR"]
	}
	if opts.BaseDir == "" {
		opts.BaseDir = os.Getenv("HEARTDESK_BASE_DIR")
	}
	if opts.BaseDir == "" || !filepath.IsAbs(opts.BaseDir) {
		return nil, fmt.Errorf("app: an absolute BaseDir is required")
	}
	if opts.ConfigDir == "" {
		opts.ConfigDir = opts.Environment["HEARTDESK_CONFIG_DIR"]
		if opts.ConfigDir == "" {
			opts.ConfigDir = filepath.Join(opts.BaseDir, "config")
		}
	}
	if opts.DataDir == "" {
		opts.DataDir = opts.Environment["HEARTDESK_DATA_DIR"]
		if opts.DataDir == "" {
			opts.DataDir = filepath.Join(opts.BaseDir, "data")
		}
	}
	if opts.DefaultTenantID == "" {
		opts.DefaultTenantID = config.DefaultTenantID
	}
	if !filepath.IsAbs(opts.ConfigDir) || !filepath.IsAbs(opts.DataDir) {
		return nil, fmt.Errorf("app: ConfigDir and DataDir must be absolute")
	}
	if opts.TenantID == "" {
		opts.TenantID = opts.DefaultTenantID
	}
	if strings.ContainsAny(opts.TenantID+opts.DefaultTenantID, "/\\.") {
		return nil, fmt.Errorf("app: invalid tenant ID")
	}
	if opts.Brand == "" {
		opts.Brand = "heartdesk"
	}
	if opts.Version == "" {
		opts.Version = "dev"
	}
	if opts.AssetVersion == "" {
		opts.AssetVersion = fmt.Sprint(time.Now().Unix())
	}
	if opts.SelfServiceName == "" {
		opts.SelfServiceName = "heartdesk"
	}
	if err := monitor.ValidateSelfServiceName(opts.SelfServiceName); err != nil {
		return nil, err
	}
	if opts.ExtractJobID != "" && strings.ContainsAny(opts.ExtractJobID, "/\\. ") {
		return nil, fmt.Errorf("app: invalid extract job ID")
	}
	var cfg *Config
	var err error
	if opts.Config != nil {
		raw, e := json.Marshal(opts.Config)
		if e != nil {
			return nil, e
		}
		cfg = &Config{}
		if e = json.Unmarshal(raw, cfg); e != nil {
			return nil, e
		}
	} else if opts.ConfigLoader != nil {
		cfg, err = opts.ConfigLoader(opts.TenantID)
	} else {
		cfg, err = LoadConfig(opts.ConfigDir, opts.TenantID)
	}
	if err != nil && !opts.SchedulerOnly {
		return nil, err
	}
	if cfg == nil && !opts.SchedulerOnly {
		return nil, fmt.Errorf("app: configuration loader returned nil")
	}
	if cfg != nil {
		cfg, err = cloneConfig(cfg)
		if err != nil {
			return nil, err
		}
		cfg.TenantID = opts.TenantID
		if cfg.SystemInfo.AppName == "" {
			cfg.SystemInfo.AppName = opts.Brand
		}
	}
	if err := validateAssets(opts.TemplateFS, opts.StaticFS); err != nil {
		return nil, err
	}
	opts.Extensions = cloneExtensions(opts.Extensions)
	if err := monitor.ValidateExtensions(opts.Extensions); err != nil {
		return nil, err
	}
	opts.Routes = append([]Route(nil), opts.Routes...)
	for i := range opts.Routes {
		opts.Routes[i].Methods = append([]string(nil), opts.Routes[i].Methods...)
	}
	opts.Notifiers = append([]Notifier(nil), opts.Notifiers...)
	opts.Jobs = append([]Job(nil), opts.Jobs...)
	if opts.SchedulerConfig != nil {
		raw, e := json.Marshal(opts.SchedulerConfig)
		if e != nil {
			return nil, e
		}
		opts.SchedulerConfig = &SchedulerConfig{}
		if e = json.Unmarshal(raw, opts.SchedulerConfig); e != nil {
			return nil, e
		}
	}
	if err := scheduler.ValidateJobPlan(opts.ExtractJobID, opts.Jobs); err != nil {
		return nil, err
	}
	// From here on process-scoped stores may initialize. Never allow a different
	// runtime to reuse partially initialized global state after a later failure.
	runtimeGate.initialized = true
	if err := heartdesk.ConfigureOperationalIdentity(opts.OperationalIdentity); err != nil {
		return nil, err
	}
	if err := monitor.ConfigureMonitorIdentity(opts.MonitorIdentity); err != nil {
		return nil, err
	}
	if err := authz.ConfigureCardAliases(opts.CardAliases); err != nil {
		return nil, err
	}
	if err := auth.ConfigureIdentity(*opts.AuthIdentity); err != nil {
		return nil, err
	}
	if err := authz.ConfigureActionPermissionAliases(opts.ActionPermissionAliases); err != nil {
		return nil, err
	}
	if opts.LicenseConfig != nil {
		material := *opts.LicenseConfig
		if err := license.Configure(material); err != nil {
			return nil, fmt.Errorf("app: license configuration: %w", err)
		}
		opts.LicenseConfig = nil
	}
	opts.Environment["HEARTDESK_BASE_DIR"] = opts.BaseDir
	opts.Environment["HEARTDESK_CONFIG_DIR"] = opts.ConfigDir
	opts.Environment["HEARTDESK_DATA_DIR"] = opts.DataDir
	opts.Environment["HEARTDESK_TENANT_ID"] = opts.TenantID
	_, explicitTOML := opts.Environment["HEARTDESK_USERS_TOML"]
	_, explicitJSON := opts.Environment["HEARTDESK_USERS_JSON"]
	if explicitJSON && !explicitTOML {
		opts.Environment["HEARTDESK_USERS_TOML"] = ""
	}
	if !explicitTOML && !explicitJSON && os.Getenv("HEARTDESK_USERS_TOML") == "" && os.Getenv("HEARTDESK_USERS_JSON") == "" {
		userPath := filepath.Join(opts.ConfigDir, "users.toml")
		if cfg != nil && cfg.Paths.UsersTOML != "" {
			userPath = cfg.Paths.UsersTOML
		}
		opts.Environment["HEARTDESK_USERS_TOML"] = userPath
	}
	if opts.SessionCookieName != "" {
		opts.Environment["HEARTDESK_SESSION_COOKIE_NAME"] = opts.SessionCookieName
	}
	if opts.CSRFCookieName != "" {
		opts.Environment["HEARTDESK_CSRF_COOKIE_NAME"] = opts.CSRFCookieName
	}
	heartdesk.ConfigureEnvironment(opts.Environment)
	monitor.ConfigureSelfServiceName(opts.SelfServiceName)
	if err := scheduler.ConfigureExtractJobID(opts.ExtractJobID); err != nil {
		return nil, err
	}
	config.DefaultTenantID = opts.DefaultTenantID
	loader := opts.ConfigLoader
	if loader == nil {
		loader = func(tenant string) (*Config, error) {
			if opts.Config != nil && tenant == opts.TenantID {
				return cfg, nil
			}
			return LoadConfig(opts.ConfigDir, tenant)
		}
	}
	config.SetRuntimeLoader(func(tenant string) (*Config, error) {
		value, err := loader(tenant)
		if err != nil {
			return nil, err
		}
		return cloneConfig(value)
	})
	if opts.Routing != nil {
		if err := routing.Configure(*opts.Routing); err != nil {
			return nil, err
		}
	}
	for i := range opts.Jobs {
		scheduler.RegisterJob(&opts.Jobs[i])
	}
	if err := monitor.ConfigureExtensions(opts.Extensions); err != nil {
		return nil, err
	}
	for _, n := range opts.Notifiers {
		alerts.RegisterNotifier(n)
	}
	if opts.SchedulerOnly {
		ctx, cancel := context.WithCancel(context.Background())
		return &Runtime{opts: opts, config: cfg, ctx: ctx, cancel: cancel, handler: http.NotFoundHandler()}, nil
	}
	verify := opts.VerifyLicense
	if verify == nil {
		verify = func(cfg *Config) error {
			return license.New().Verify(cfg.VendorLicense.TenantID+"-monitor", cfg.VendorLicense.LicenseKey)
		}
	}
	if err := verify(cfg); err != nil {
		return nil, fmt.Errorf("license verification failed: %w", err)
	}
	rt, err := bootstrap(opts, cfg)
	if err != nil {
		return nil, err
	}
	rt.opts = opts
	rt.ctx, rt.cancel = context.WithCancel(context.Background())
	var reportHook func(*Config, AgentReport)
	if opts.OnReportSaved != nil {
		reportHook = func(cfg *Config, report AgentReport) {
			ctx := rt.monitor.ExtensionContext(nil)
			ctx.Config = cfg
			ctx.RawAgentID = report.AgentID
			ctx.AgentID = report.AgentID
			opts.OnReportSaved(ctx, report)
		}
	}
	if err := monitor.ConfigureReportObserver(reportHook); err != nil {
		_ = rt.Close()
		return nil, err
	}
	return rt, nil
}

func (r *Runtime) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		r.lifecycleMu.Lock()
		if r.closed.Load() || !r.prepared.Load() {
			r.lifecycleMu.Unlock()
			http.Error(w, "runtime not ready", http.StatusServiceUnavailable)
			return
		}
		r.workers.Add(1)
		r.lifecycleMu.Unlock()
		defer r.workers.Done()
		ctx, cancel := context.WithCancel(q.Context())
		stop := context.AfterFunc(r.ctx, cancel)
		defer stop()
		defer cancel()
		r.handler.ServeHTTP(w, q.WithContext(ctx))
	})
}

// Prepare restores durable stores and revocations before the Handler can accept
// requests. It opens no listener, starts no jobs and runs no privileged commands.
// Embedders serving Handler with their own HTTP server must call Prepare first.
func (r *Runtime) Prepare(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.lifecycleMu.Lock()
	if r.closed.Load() {
		r.lifecycleMu.Unlock()
		return fmt.Errorf("app: runtime closed")
	}
	r.workers.Add(1)
	r.lifecycleMu.Unlock()
	defer r.workers.Done()
	r.startupOnce.Do(func() {
		if r.config != nil && !r.opts.SchedulerOnly {
			r.startupErr = r.initializeState()
		}
		if r.startupErr == nil {
			r.prepared.Store(true)
		}
	})
	return r.startupErr
}

func (r *Runtime) Run(ctx context.Context) error {
	if err := r.beginRun(false); err != nil {
		return err
	}
	defer r.workers.Done()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.Prepare(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.ctx.Err(); err != nil {
		return err
	}
	r.maintenanceOnce.Do(func() {
		if !r.opts.SkipStartupMaintenance {
			if err := monitor.SyncIPManage(true); err != nil {
				log.Printf("SyncIPManage failed at startup: %v", err)
			}
		}
	})
	listener, err := net.Listen("tcp", r.addr)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: r.Handler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	errs := make(chan error, 1)
	go func() { errs <- srv.Serve(listener) }()
	select {
	case err := <-errs:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
	case <-r.ctx.Done():
	}
	shutdown, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return srv.Shutdown(shutdown)
}

func (r *Runtime) RunScheduler(ctx context.Context) error {
	if err := r.beginRun(true); err != nil {
		return err
	}
	defer r.workers.Done()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.Prepare(ctx); err != nil {
		return err
	}
	cfg := r.opts.SchedulerConfig
	if cfg == nil && r.config != nil {
		cfg = r.config.ToSchedulerConfig()
	}
	if cfg == nil {
		var err error
		cfg, err = config.TryLoadSchedulerConfig()
		if err != nil {
			return err
		}
	}
	s := scheduler.NewScheduler(cfg, log.Default())
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := r.ctx.Err(); err != nil {
		return err
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-r.ctx.Done():
			cancel()
		case <-runCtx.Done():
		}
	}()
	err := s.Run(runCtx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func (r *Runtime) Close() error {
	r.closeOnce.Do(func() {
		r.lifecycleMu.Lock()
		r.closed.Store(true)
		if r.cancel != nil {
			r.cancel()
		}
		r.lifecycleMu.Unlock()
		r.workers.Wait()
		if r.reportDB != nil {
			r.closeErr = r.reportDB.Close()
		}
		if r.ownedDB != nil {
			if err := r.ownedDB.Close(); r.closeErr == nil {
				r.closeErr = err
			}
		}
		if r.ownedAuditDB {
			auditdb.Close()
		}
	})
	return r.closeErr
}

func (r *Runtime) beginRun(scheduler bool) error {
	r.lifecycleMu.Lock()
	defer r.lifecycleMu.Unlock()
	if r.closed.Load() {
		return fmt.Errorf("app: runtime closed")
	}
	if !scheduler && r.opts.SchedulerOnly {
		return fmt.Errorf("app: scheduler-only runtime cannot serve the monitor")
	}
	if scheduler {
		if r.schedulerStarted {
			return fmt.Errorf("app: scheduler already started")
		}
		r.schedulerStarted = true
	} else {
		if r.monitorStarted {
			return fmt.Errorf("app: monitor already started")
		}
		r.monitorStarted = true
	}
	r.workers.Add(1)
	return nil
}

func ReloadConfigCache() { config.ReloadConfigCache() }

func cloneConfig(value *Config) (*Config, error) {
	if value == nil {
		return nil, fmt.Errorf("app: nil configuration")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	copy := &Config{}
	if err := json.Unmarshal(data, copy); err != nil {
		return nil, err
	}
	return copy, nil
}
