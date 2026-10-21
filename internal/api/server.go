package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// ServerConfig stores server options
type ServerConfig struct {
	Port      int
	StaticDir string
}

// Server encapsulates the HTTP server
type Server struct {
	httpServer *http.Server
	config     ServerConfig
}

// NewServer initializes the server with router and static file serving
func NewServer(cfg ServerConfig, handler *Handler) *Server {
	mux := http.NewServeMux()

	// Register API routes
	handler.RegisterRoutes(mux)

	// Serve static files if directory exists
	if cfg.StaticDir != "" {
		if _, err := os.Stat(cfg.StaticDir); err == nil {
			fs := http.FileServer(http.Dir(cfg.StaticDir))
			mux.Handle("/", fs)
		} else {
			// Try relative to workspace
			absPath, _ := filepath.Abs(cfg.StaticDir)
			if _, err := os.Stat(absPath); err == nil {
				fs := http.FileServer(http.Dir(absPath))
				mux.Handle("/", fs)
			}
		}
	}

	// Logging & CORS middleware
	wrappedHandler := corsAndLoggingMiddleware(mux)

	addr := fmt.Sprintf(":%d", cfg.Port)
	return &Server{
		config: cfg,
		httpServer: &http.Server{
			Addr:         addr,
			Handler:      wrappedHandler,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
			IdleTimeout:  60 * time.Second,
		},
	}
}

// Start runs the HTTP server
func (s *Server) Start() error {
	log.Printf("[ACL Server] Listening on http://localhost:%d\n", s.config.Port)
	log.Printf("[ACL Server] API endpoints available at http://localhost:%d/api/v1/\n", s.config.Port)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully stops the server
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func corsAndLoggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		start := time.Now()
		next.ServeHTTP(w, r)
		duration := time.Since(start)

		// Simple access logging
		log.Printf("%s %s %s - %v", r.Method, r.URL.Path, r.RemoteAddr, duration)
	})
}
