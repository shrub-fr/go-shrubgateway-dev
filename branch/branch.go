// Copyright 2019 The shrub.fr Authors.
// Use of this source code is governed by the CC0 1.0 Universal license
// that can be found at https://creativecommons.org/publicdomain/zero/1.0/

package branch

import (
	"bufio"
	"context"
	"encoding/base32"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"github.com/shrub-fr/go-shrubgateway/gimli"
)

var shrubberyDir string // working directory

func init() {
	var err error
	shrubberyDir, err = os.Getwd()
	log.Fatal(err, "failed to find the working directory")
}

var base32Encoding = base32.NewEncoding("0123456789abcdefghijklmnopqrstuv").WithPadding(base32.NoPadding)

var errInvalidData = errors.New("shrubgateway: the application/branch file contains invalid data")

// reader reads the content of a shoot,
// following the specifications of draft-shrub.fr-shrubbery available at
// https://github.com/shrub-fr/spec-shrub/blob/master/shrubbery.md#shootstreaming-algorithm
type reader struct {
	cancel        func()    // to cancel the reading of the application/branch file
	payload       io.Reader // reader of the application/branch file
	isFirstChunck bool      // true if the first chunck of content has yet to be read
	isLastChunck  bool      // true if the last chunck of content has been put in cache
	tag           []byte    // tag of the next chunk to be read
	cache         []byte    // cache of the current decrypted chunk
	pathState     *[48]byte // state of a sponge which has absorbed the shoot's path
	err           error     // the error encountered by the reader, if any
}

var errAbortedReader = errors.New("shrubgateway: the reader has been aborted")

func (r *reader) Close() error {
	r.cancel()
	if r.err == nil {
		r.err = errAbortedReader
	}
	return r.err
}

func (r *reader) Read(p []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}

	if len(r.cache) == 0 {
		if r.isLastChunck {
			r.err = io.EOF
			return 0, r.err
		}

		chunk := make([]byte, 2432)
		n, err := io.ReadFull(r.payload, chunk)
		if err != nil && err != io.ErrUnexpectedEOF {
			r.cancel()
			r.err = err
			return 0, r.err
		}

		if n < 48 || n%16 != 0 {
			r.cancel()
			r.err = errInvalidData
			return 0, r.err
		}

		s := gimli.CopySponge(r.pathState)
		nonce := chunk[n-32 : n]
		gimli.Absorb(s, nonce)
		cipher := chunk[:n-32]
		gimli.Decrypt(s, cipher)
		tag := gimli.Finalize(s)
		if !isEqual(tag, r.tag) {
			r.cancel()
			r.err = errInvalidData
			return 0, r.err
		}

		if n != 2432 && chunk[n-33]&64 == 0 {
			r.cancel()
			r.err = errInvalidData
			return 0, r.err
		}

		if r.isFirstChunck && chunk[n-33]&128 == 0 {
			r.cancel()
			r.err = errInvalidData
			return 0, r.err
		}
		r.isFirstChunck = false

		l := int(chunk[n-34]) + int(chunk[n-33]&63)*256
		if n-32 < 2+l {
			r.cancel()
			r.err = errInvalidData
			return 0, r.err
		}
		r.cache = chunk[:n-32-l-2]

		if chunk[1]&64 != 0 {
			r.isLastChunck = true
		} else {
			copy(r.tag, nonce)
		}
	}

	n := copy(p, r.cache)
	r.cache = r.cache[n:]
	return n, nil
}

// NewShoot returns an io.Reader which reads from the content of a shoot,
// following the specifications of draft-shrub.fr-shrubbery available at
// https://github.com/shrub-fr/spec-shrub/blob/master/shrubbery.md#shootstreaming-algorithm
//
// 'host' is the hostname from where the application/branch file must be
// retrieved using the CORS protocol without credentials, with an opaque origin
// and with the mapping of .Well-Known URLs defined at
// https://github.com/shrub-fr/spec-shrub/blob/master/shrubbery.md#the-well-known-uris-suffix-shrubbery
//
// 'rootTag' is the base32 encoding of the tag of the root of the shrub
// containing the shoot.
//
// 'root' is the base32 decoding of rootTag.
//
// 'pathState' is the state of a Gimli Sponge which has absorbed
// the path of the shoot.
//
// 'tr' is a transport to use to retrieve the application/branch file which
// contains the shoot.
func NewShoot(parentCtx context.Context, host, rootTag string, root []byte, pathState *[48]byte, tr http.RoundTripper) (io.ReadCloser, error) {

	s := gimli.CopySponge(pathState)
	pathTag := gimli.Finalize(s)
	branchID := base32Encoding.EncodeToString(pathTag)

	ctx, cancel := context.WithCancel(parentCtx)
	payload, err := getPayload(ctx, host, rootTag, branchID, tr)
	if err != nil {
		cancel()
		return nil, err
	}

	parent := make([]byte, 64)
	child := make([]byte, 64)
	copy(parent, root)

	for {
		_, err = io.ReadFull(payload, child)
		if err != nil {
			cancel()
			return nil, err
		}

		s = gimli.Sap()
		gimli.Absorb(s, child)
		tag := gimli.Finalize(gimli.CopySponge(s))
		if !isEqual(tag, parent[:32]) && !isEqual(tag, parent[32:]) {
			break
		}

		copy(parent, child)
	}

	gimli.Absorb(s, pathTag)
	tag := gimli.Finalize(s)
	if !isEqual(tag, parent[:32]) && !isEqual(tag, parent[32:]) {
		cancel()
		return nil, errInvalidData
	}

	copy(tag, child[32:])
	isFirstChunck := true
	isLastChunck := false
	cache := make([]byte, 0)
	return &reader{cancel, payload, isFirstChunck, isLastChunck, tag, cache, pathState, nil}, nil
}

// isEqual does not need to be constant-time
func isEqual(s, t []byte) bool {
	for i, b := range s {
		if t[i] != b {
			return false
		}
	}
	return true
}

var errBadCORS = errors.New("shrubgateway: invalid CORS response")

// getPayload returns a reader which reads the application/branch file.
func getPayload(ctx context.Context, host, rootTag, branchID string, tr http.RoundTripper) (io.Reader, error) {
	filePath := filepath.Join(shrubberyDir, rootTag, branchID)
	f, err := os.Open(filePath)
	if err == nil {
		go fileCloser(ctx, f)
		return bufio.NewReaderSize(f, 1<<14), nil
	}

	// wellKnownURL uses the mapping of .Well-Known URLs defined in
	// https://github.com/shrub-fr/spec-shrub/blob/master/shrubbery.md#the-well-known-uris-suffix-shrubbery
	wellKnownURL := "https://" + host + "/.well-known/shrubbery/" + rootTag + "/" + branchID
	req, err := http.NewRequest(http.MethodGet, wellKnownURL, nil)
	if err != nil {
		return nil, err
	}
	// the request must be a valid CORS request with an opaque origin
	req.Header.Set("Origin", "null")

	resp, err := tr.RoundTrip(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}

	accessControl := resp.Header.Get("Access-Control-Allow-Origin")
	// the response must be a valid CORS response
	if accessControl != "null" && accessControl != "*" {
		return nil, errBadCORS
	}

	if resp.StatusCode == http.StatusOK {
		return bufio.NewReaderSize(resp.Body, 1<<14), nil
	}

	return nil, errBadCORS
}

func fileCloser(ctx context.Context, f io.Closer) {
	<-ctx.Done()
	f.Close()
}
