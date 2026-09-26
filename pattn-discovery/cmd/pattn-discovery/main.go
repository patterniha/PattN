package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"

	"pattn-discovery/engine"
	"pattn-discovery/protocol"
)

func main() {
	if err := run(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, in io.Reader, out io.Writer) error {
	eng := engine.New()
	scanner := bufio.NewScanner(in)
	// Requests can carry large target batches; keep framing bounded but well above Scanner's default 64 KiB.
	scanner.Buffer(make([]byte, 64*1024), 16*1024*1024)
	enc := json.NewEncoder(out)
	enc.SetEscapeHTML(false)
	var writeMu sync.Mutex
	emit := func(response protocol.Response) error {
		writeMu.Lock()
		defer writeMu.Unlock()
		return enc.Encode(response)
	}
	var streams sync.WaitGroup
	for scanner.Scan() {
		var req protocol.Request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
			if err := emit(protocol.Response{Version: protocol.Version, Error: &protocol.Error{Code: "invalid_json", Message: err.Error()}}); err != nil {
				return err
			}
			continue
		}
		if engine.IsStreamingMethod(req.Method) {
			streams.Add(1)
			go func(request protocol.Request) {
				defer streams.Done()
				_ = eng.HandleStream(ctx, request, emit)
			}(req)
			continue
		}
		if err := eng.HandleStream(ctx, req, emit); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	streams.Wait()
	return nil
}
