package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"go-acl-bitmask/internal/api"
	"go-acl-bitmask/pkg/acl"
)

func main() {
	port := flag.Int("port", 8080, "HTTP server port")
	staticDir := flag.String("static", "./web/static", "Path to static files directory")
	flag.Parse()

	// Initialize Registry and Evaluator
	registry := acl.DefaultRegistry()
	evaluator := acl.NewEvaluator(registry)
	handler := api.NewHandler(evaluator)

	cfg := api.ServerConfig{
		Port:      *port,
		StaticDir: *staticDir,
	}

	server := api.NewServer(cfg, handler)

	// Print quick sample demo info
	printDemoInfo(*port)

	// Channel to listen for errors coming from the listener
	serverErrors := make(chan error, 1)

	go func() {
		if err := server.Start(); err != nil && err != http.ErrServerClosed {
			serverErrors <- err
		}
	}()

	// Channel to listen for interrupt or terminate signal from the OS
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt, syscall.SIGTERM)

	select {
	case err := <-serverErrors:
		log.Fatalf("Error starting server: %v", err)

	case sig := <-shutdown:
		log.Printf("Signal %v received, shutting down gracefully...", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			log.Printf("Graceful shutdown failed: %v", err)
			_ = server.Shutdown(ctx)
		}
		log.Println("Server stopped cleanly.")
	}
}

func printDemoInfo(port int) {
	// Sample 64-bit ACL:
	// G1: Sub 1, Obj 2, READ(1)|WRITE(2) -> 0x53
	// C1: 0x01 (Requires bit 0 active)
	// G2: Sub 2, Obj 1, CONNECT(1)|PUBLISH(2) -> 0x93
	// C2: 0x02
	g1 := acl.NewGroup(1, 2, acl.Right1|acl.Right2)
	c1 := acl.ContextGroup(0x01)
	g2 := acl.NewGroup(2, 1, acl.Right1|acl.Right2)
	c2 := acl.ContextGroup(0x02)

	sampleACL := acl.BuildACL(
		acl.Pair{Group: g1, Context: c1},
		acl.Pair{Group: g2, Context: c2},
	)

	fmt.Println("==================================================================")
	fmt.Println("      64-bit ACL Bitmask Service (Go)")
	fmt.Println("==================================================================")
	fmt.Printf(" Server running at: http://localhost:%d/\n", port)
	fmt.Printf(" Sample 64-bit ACL: %d (%s)\n", sampleACL.Uint64(), sampleACL.Hex())
	fmt.Println(" Endpoints:")
	fmt.Printf("   POST http://localhost:%d/api/v1/check\n", port)
	fmt.Printf("   POST http://localhost:%d/api/v1/check-batch\n", port)
	fmt.Printf("   POST http://localhost:%d/api/v1/encode\n", port)
	fmt.Printf("   GET  http://localhost:%d/api/v1/decode?acl=<uint64|0xHex>\n", port)
	fmt.Printf("   GET  http://localhost:%d/api/v1/groups\n", port)
	fmt.Println("==================================================================")
}
