// Copyright 2019 The shrub.fr Authors.
// Use of this source code is governed by the CC0 1.0 Universal license
// that can be found at https://creativecommons.org/publicdomain/zero/1.0/

// package shrubgateway starts a web server listening
// for TLS connections on the local host's loopback interface on port 58273,
// using the local CA at <user's home directory>/.shrubgateway
//
// This server implements the protocol associated
// to the Shrub https subscheme, as defined in
// draft-shrub.fr-shrub at
// https://github.com/shrub-fr/spec-shrub/blob/master/shrub.md
//
// However, the server tries to retrieve the application/branch file
// from the working directory first, before going to the network
// if the file is not found locally.
package main

import (
	"crypto/tls"
	"encoding/base32"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"

	"github.com/shrub-fr/go-shrubgateway-dev/branch"
	"github.com/shrub-fr/go-shrubgateway/gimli"
	"github.com/shrub-fr/go-shrubgateway/mkcert"

	"golang.org/x/net/http2/hpack"
)

var base32Encoding = base32.NewEncoding("0123456789abcdefghijklmnopqrstuv").WithPadding(base32.NoPadding)

// transports contains the pools of outgoing HTTP connections.
// For privacy reasons, a different pool of outgoing connections
// is associated to each incoming connection.
var transports = &sync.Map{}

func main() {
	http.HandleFunc("/", handler)

	server := &http.Server{
		TLSConfig: &tls.Config{GetCertificate: mkcert.GetCertificate},
		Addr:      ":58273",
		ConnState: manageConnCache,
	}

	fmt.Println("shrubgateway-dev v0.2.0 (Go)")
	fmt.Println("For more information, go to https://shrub.fr/")
	log.Fatal(server.ListenAndServeTLS("", ""))
}

// handler implements the protocol associated to the Shrub https subscheme,
// as defined in draft-shrub.fr-shrub at
// https://github.com/shrub-fr/spec-shrub/blob/master/shrub.md
func handler(w http.ResponseWriter, req *http.Request) {
	if req.Method == http.MethodOptions {
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusOK)
		return
	}

	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Allow", "GET, HEAD, OPTIONS")
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("shrubgateway: the request's method MUST be GET, HEAD or OPTIONS"))
		return
	}

	host, rootTag, root, keyState, err := splitHost(req)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(err.Error()))
		return
	}

	pathState := keyState
	gimli.Absorb(pathState, gimli.Pad(req.URL.EscapedPath()))
	transport, _ := transports.Load(req.RemoteAddr)
	tr, _ := transport.(http.RoundTripper)
	shootContent, err := branch.NewShoot(req.Context(), host, rootTag, root, pathState, tr)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(err.Error()))
		return
	}

	size := make([]byte, 8)
	_, err = io.ReadFull(shootContent, size)
	if err != nil {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(err.Error()))
		return
	}
	headerBlockSize := int64(size[0]) + int64(size[1])<<8 + int64(size[2])<<16
	explanation := "shrubgateway: the size of the response's header block is greater than 1MB"
	if 1<<20 < headerBlockSize || size[3] != 0 || size[4] != 0 || size[5] != 0 || size[6] != 0 || size[7] != 0 {
		shootContent.Close()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(explanation))
		return
	}

	status := 0
	sizeHeader := 0
	emitFunc := func(hf hpack.HeaderField) {
		if status == 0 {
			if hf.Name != ":status" {
				// status == 1 means that an error was encountered during
				// the decoding of the headers
				status = 1
				explanation = "shrubgateway: the name of the first header of the response's header block is not ':status'"
				return
			}
			status, err = strconv.Atoi(hf.Value)
			if err != nil {
				status = 1
				explanation = "shrubgateway: the value of the first header of the response's header block is invalid"
				return
			}
			if status < 200 || 499 < status {
				status = 1
				explanation = "shrubgateway: the value of the first header of the response's header block is invalid"
				return
			}
			return
		}

		if status == 1 {
			return
		}

		if hf.IsPseudo() {
			status = 1
			explanation = "shrubgateway: the response's header block contains more than one pseudo-header"
			return
		}

		if 1<<20 < sizeHeader {
			status = 1
			return
		}

		w.Header().Add(hf.Name, hf.Value)
		sizeHeader += int(hf.Size())
	}
	dec := hpack.NewDecoder(0, emitFunc)
	dec.SetAllowedMaxDynamicTableSize(0)
	dec.SetMaxStringLength(1 << 16)

	_, err = io.CopyN(dec, shootContent, headerBlockSize)
	if err != nil {
		shootContent.Close()
		for key := range w.Header() {
			w.Header().Del(key)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(err.Error()))
		return
	}
	if status == 1 {
		shootContent.Close()
		for key := range w.Header() {
			w.Header().Del(key)
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusBadGateway)
		w.Write([]byte(explanation))
		return
	}

	w.WriteHeader(status)
	if req.Method == http.MethodHead {
		shootContent.Close()
		return
	}

	_, err = io.Copy(w, shootContent)
	shootContent.Close()
	if err != nil {
		panic(http.ErrAbortHandler)
	}

}

// For privacy reasons, pools of outgoing connections in 'transports'
// are ephemeral and their lifetime is the same as the incoming connections
// they are used for.
func manageConnCache(c net.Conn, s http.ConnState) {
	remoteAddr := c.RemoteAddr().String()

	if s == http.StateNew {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		transports.Store(remoteAddr, transport)
	}

	if s == http.StateClosed {
		transports.Delete(remoteAddr)
	}
}

var errBadHost = errors.New("shrubgateway: the host field of the request's URL is invalid")

func splitHost(req *http.Request) (host string, rootTag string, root []byte, keyState *[48]byte, err error) {

	hostname, _, err := net.SplitHostPort(req.URL.Host)
	if hostname == "" {
		hostname, _, err = net.SplitHostPort(req.Host)
	}
	if err != nil {
		return "", "", nil, nil, err
	}

	l := len(hostname)
	if l < 170 {
		return "", "", nil, nil, errBadHost
	}
	suffix := hostname[l-10:]
	if suffix != ".localhost" {
		return "", "", nil, nil, errBadHost
	}

	host = hostname[:l-169]
	rootTag = hostname[l-62 : l-10]
	root, err = base32Encoding.DecodeString(rootTag)
	if err != nil {
		return "", "", nil, nil, errBadHost
	}
	keyTag := hostname[l-115 : l-63]
	key, err := base32Encoding.DecodeString(keyTag)
	if err != nil {
		return "", "", nil, nil, errBadHost
	}
	keyState = gimli.Sap()
	gimli.Absorb(keyState, key)
	return host, rootTag, root, keyState, nil
}
