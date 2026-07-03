package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"
)

// lokiStream is one labeled stream in a Loki push payload. values are
// [ "<unix-nanos>", "<line>" ] pairs, strictly increasing per stream.
type lokiStream struct {
	Stream map[string]string `json:"stream"`
	Values [][2]string       `json:"values"`
}

type lokiPush struct {
	Streams []lokiStream `json:"streams"`
}

// pushLoki sends one labeled stream (the lines of a single guest audit file) to
// Loki. Timestamps are synthesized as base+index ns so ordering is preserved and
// Loki's per-stream monotonicity requirement is satisfied; the real event times
// live inside the JSON lines themselves.
func pushLoki(ctx context.Context, url string, labels map[string]string, lines []string, base time.Time) error {
	if len(lines) == 0 {
		return nil
	}
	values := make([][2]string, 0, len(lines))
	for i, ln := range lines {
		ts := strconv.FormatInt(base.Add(time.Duration(i)).UnixNano(), 10)
		values = append(values, [2]string{ts, ln})
	}
	body, err := json.Marshal(lokiPush{Streams: []lokiStream{{Stream: labels, Values: values}}})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url+"/loki/api/v1/push", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("loki push %s: http %d", labels["stream"], resp.StatusCode)
	}
	return nil
}
