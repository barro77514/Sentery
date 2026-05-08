package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

type Proxy struct {
	caCert *x509.Certificate
	caKey  interface{}
	certs  map[string]*tls.Certificate
	mu     sync.Mutex
}

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

	w.WriteHeader(http.StatusOK)
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		log.Printf("Hijack error: %v", err)
		return
	}

	host, _, _ := net.SplitHostPort(r.Host)
	if host == "" {
		host = r.Host
	}

	tlsCert, err := p.getCert(host)
	if err != nil {
		log.Printf("Cert generation error for %s: %v", host, err)
		clientConn.Close()
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake error for %s: %v", host, err)
		tlsConn.Close()
		return
	}

	// Now handle the decrypted HTTP requests over the TLS connection
	p.handleDecryptedHTTP(tlsConn, host)
}

func (p *Proxy) handleDecryptedHTTP(conn net.Conn, host string) {
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Host == "" {
				r.URL.Host = host
				r.URL.Scheme = "https"
			}
			p.handleHTTP(w, r)
		}),
	}
	server.Serve(&singleConnListener{conn: conn})
}

type singleConnListener struct {
	conn net.Conn
	once sync.Once
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	l.once.Do(func() {
		c = l.conn
	})
	if c == nil {
		return nil, io.EOF
	}
	return c, nil
}

func (l *singleConnListener) Close() error   { return nil }
func (l *singleConnListener) Addr() net.Addr { return l.conn.LocalAddr() }

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	urlStr := r.URL.String()
	if !strings.HasPrefix(urlStr, "http") {
		urlStr = "https://" + r.Host + urlStr
	}

	outReq, err := http.NewRequest(r.Method, urlStr, bytes.NewBuffer(body))
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

	respBody, _ := io.ReadAll(resp.Body)

	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)

	data := TrafficData{
		Method:           r.Method,
		URL:              urlStr,
		RequestBody:      string(body),
		ResponseStatus:   resp.StatusCode,
		ResponseBodySize: len(respBody),
	}
	p.sendToOrchestrator(data)
	SaveTraffic(data)
}

func (p *Proxy) sendToOrchestrator(data TrafficData) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return
	}
	resp, err := http.Post("http://localhost:8000/traffic", "application/json", bytes.NewBuffer(jsonData))
	if err == nil {
		resp.Body.Close()
	}
}

func (p *Proxy) getCert(host string) (*tls.Certificate, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if cert, ok := p.certs[host]; ok {
		return cert, nil
	}

	der, priv, err := GenerateCert(host, p.caCert, p.caKey.(*rsa.PrivateKey))
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	p.certs[host] = cert
	return cert, nil
}

func main() {
	InitDB()

	caCertFile := "ca.crt"
	caKeyFile := "ca.key"

	var caCertDER []byte
	var caKey *rsa.PrivateKey

	if _, err := os.Stat(caCertFile); os.IsNotExist(err) {
		der, key, err := GenerateCA()
		if err != nil {
			log.Fatal(err)
		}
		SavePEM(caCertFile, "CERTIFICATE", der)
		keyBytes := x509.MarshalPKCS1PrivateKey(key)
		SavePEM(caKeyFile, "RSA PRIVATE KEY", keyBytes)
		caCertDER = der
		caKey = key
	} else {
		caCertPEM, _ := os.ReadFile(caCertFile)
		block, _ := pem.Decode(caCertPEM)
		caCertDER = block.Bytes
		caKeyPEM, _ := os.ReadFile(caKeyFile)
		keyBlock, _ := pem.Decode(caKeyPEM)
		caKey, _ = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	}

	caCert, _ := x509.ParseCertificate(caCertDER)

	proxy := &Proxy{
		caCert: caCert,
		caKey:  caKey,
		certs:  make(map[string]*tls.Certificate),
	}

	log.Println("Starting MITM proxy on :8080")
	if err := http.ListenAndServe(":8080", proxy); err != nil {
		log.Fatal(err)
	}
}
