package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"time"
)

func main() {
	httpAddr := flag.String("http", "127.0.0.1:0", "HTTP and WS listener")
	tlsAddr := flag.String("https", "127.0.0.1:0", "TLS and WSS listener")
	management := flag.String("management", "127.0.0.1:0", "management listener")
	output := flag.String("output", "", "new run output directory (default temporary directory)")
	flag.Parse()
	if *output == "" {
		dir, err := os.MkdirTemp("", "fastls-lab-")
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		*output = dir
	}
	dir, err := filepath.Abs(*output)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	lab, err := Start(Config{HTTPAddr: *httpAddr, TLSAddr: *tlsAddr, ManagementAddr: *management, Output: dir})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer lab.Close()
	json.NewEncoder(os.Stdout).Encode(lab.Manifest)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	<-ctx.Done()
	lab.Close()
	time.Sleep(10 * time.Millisecond)
}
