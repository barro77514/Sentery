package main

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
)

type Proxy struct{}

type TrafficData struct {
	Method           string `json:"method"`
	URL              string `json:"url"`
	RequestBody      string `json:"request_body"`
	ResponseStatus   int    `json:"response_status"`
	ResponseBodySize int    `json:"response_body_size"`
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Intercepted %s %s", r.Method, r.URL.String())

	if r.Method == http.MethodConnect {
		p.handleConnect(w, r)
		return
	}

	p.handleHTTP(w, r)
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	log.Printf("Handling CONNECT for %s", r.Host)
	destConn, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		destConn.Close()
		return
	}

	go p.transfer(destConn, clientConn)
	go p.transfer(clientConn, destConn)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	// Intercept and log request body
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	log.Printf("Request Body: %s", string(body))

	// Prepare outbound request
	outReq, err := http.NewRequest(r.Method, r.URL.String(), bytes.NewBuffer(body))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	for key, values := range r.Header {
		for _, value := range values {
			if strings.ToLower(key) != "proxy-connection" {
				outReq.Header.Add(key, value)
			}
		}
	}

	client := &http.Client{}
	resp, err := client.Do(outReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Intercept and log response body
	respBody, _ := io.ReadAll(resp.Body)
	log.Printf("Response Status: %d", resp.StatusCode)
	log.Printf("Response Body size: %d", len(respBody))

	// Copy response headers and body to client
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	// Send to Orchestrator
	p.sendToOrchestrator(TrafficData{
		Method:           r.Method,
		URL:              r.URL.String(),
		RequestBody:      string(body),
		ResponseStatus:   resp.StatusCode,
		ResponseBodySize: len(respBody),
	})
}

func (p *Proxy) sendToOrchestrator(data TrafficData) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		log.Printf("Error marshaling traffic data: %v", err)
		return
	}

	resp, err := http.Post("http://localhost:8000/traffic", "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		log.Printf("Error sending to orchestrator: %v", err)
		return
	}
	defer resp.Body.Close()
}

func (p *Proxy) transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func main() {
	proxy := &Proxy{}
	log.Println("Starting proxy on :8080")
	if err := http.ListenAndServe(":8080", proxy); err != nil {
		log.Fatal(err)
	}
}
