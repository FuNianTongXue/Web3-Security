package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"scaudit/internal/webapp"
)

func main() {
	port := flag.Int("port", 8088, "listen port")
	host := flag.String("host", "127.0.0.1", "listen host")
	noOpen := flag.Bool("no-open", false, "do not auto-open browser")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *host, *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s failed: %v", addr, err)
	}
	defer ln.Close()

	h, err := webapp.NewHandler()
	if err != nil {
		log.Fatal(err)
	}

	url := "http://" + addr
	if !*noOpen {
		go func() {
			time.Sleep(450 * time.Millisecond)
			openBrowser(url)
		}()
	}

	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Serve(ln)
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	log.Printf("SCaudit desktop mode started: %s", url)
	select {
	case sig := <-sigCh:
		log.Printf("received signal %s, shutting down", sig.String())
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatal(err)
		}
		return
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("graceful shutdown failed: %v, forcing close", err)
		_ = srv.Close()
	}

	if err := <-errCh; err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Printf("server stop error: %v", err)
	}
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
