// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tls

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"
)

// serverHandshakeState contains details of a server handshake in progress.
// It's discarded once the handshake has completed.
type serverHandshakeState struct {
	c                     *Conn
	suite                 *cipherSuite
	masterSecret          []byte
	cachedClientHelloInfo *ClientHelloInfo
	clientHello           *clientHelloMsg
	hello                 *serverHelloMsg
	cert                  *Certificate
	privateKey            crypto.PrivateKey

	// A marshalled DelegatedCredential to be sent to the client in the
	// handshake.
	delegatedCredential []byte

	// TLS 1.0-1.2 fields
	ellipticOk      bool
	ecdsaOk         bool
	rsaDecryptOk    bool
	rsaSignOk       bool
	sessionState    *sessionState
	finishedHash    finishedHash
	certsFromClient [][]byte

	// TLS 1.3 fields
	hello13Enc        *encryptedExtensionsMsg
	keySchedule       *keySchedule13
	clientFinishedKey []byte
	hsClientCipher    interface{}
	appClientCipher   interface{}
}

// serverHandshake performs a TLS handshake as a server.
// c.out.Mutex <= L; c.handshakeMutex <= L.
func (c *Conn) serverHandshake() error {
	// If this is the first server handshake, we generate a random key to
	// encrypt the tickets with.
	c.config.serverInitOnce.Do(func() { c.config.serverInit(nil) })

	hs := serverHandshakeState{
		c: c,
	}
	c.in.traceErr = hs.traceErr
	c.out.traceErr = hs.traceErr
	isResume, err := hs.readClientHello()

	// [Psiphon]
	// The ClientHello with the passthrough message is now available. Route the
	// client to passthrough based on message inspection. This code assumes the
	// client TCP conn has been wrapped with recorderConn, which has recorded
	// all bytes sent by the client, which will be replayed, byte-for-byte, to
	// the passthrough; as a result, passthrough clients will perform their TLS
	// handshake with the passthrough target, receive its certificate, and in the
	// case of HTTPS, receive the passthrough target's HTTP responses.
	//
	// Passthrough is also triggered if readClientHello fails. E.g., on other
	// invalid input cases including "tls: handshake message of length..." or if
	// the ClientHello is otherwise invalid. This ensures that clients sending
	// random data will be relayed to the passthrough and not receive a
	// distinguishing error response.
	//
	// The `tls` API performs handshakes on demand. E.g., the first call to
	// tls.Conn.Read will perform a handshake if it's not yet been performed.
	// Consumers such as `http` may call Read and then Close. To minimize code
	// changes, in the passthrough case the ownership of Conn.conn, the client
	// TCP conn, is transferred to the passthrough relay and a closedConn is
	// substituted for Conn.conn. This allows the remaining `tls` code paths to
	// continue reference a net.Conn, albeit one that is closed, so Reads and
	// Writes will fail.

	if c.config.PassthroughAddress != "" {

		doPassthrough := false

		if err != nil {
			doPassthrough = true
			err = fmt.Errorf("passthrough: %s", err)
		}

		clientAddr := c.conn.RemoteAddr().String()
		clientIP, _, _ := net.SplitHostPort(clientAddr)

		if !doPassthrough {
			if !c.config.PassthroughVerifyMessage(hs.clientHello.random) {

				c.config.PassthroughLogInvalidMessage(clientIP)

				doPassthrough = true
				err = errors.New("passthrough: invalid client random")
			}
		}

		if !doPassthrough {
			if !c.config.PassthroughHistoryAddNew(
				clientIP, hs.clientHello.random) {

				doPassthrough = true
				err = errors.New("passthrough: duplicate client random")
			}
		}

		// Call GetReadBuffer, in both passthrough and non-passthrough cases, to
		// stop buffering all read bytes.

		passthroughReadBuffer := c.conn.(*recorderConn).GetReadBuffer().Bytes()

		if doPassthrough {

			// When performing passthrough, we must exit at the "return err" below.
			// This is a failsafe to ensure err is always set.
			if err == nil {
				err = errors.New("passthrough: missing error")
			}

			// Modifying c.conn directly is safe only because Conn.Handshake, which
			// calls Conn.serverHandshake, is holding c.handshakeMutex and c.in locks,
			// and because of the serial nature of c.conn access during the handshake
			// sequence.
			conn := c.conn
			c.conn = newClosedConn(conn)

			go func() {

				// Perform the passthrough relay.
				//
				// Limitations:
				//
				// - The local TCP stack may differ from passthrough target in a
				//   detectable way.
				//
				// - There may be detectable timing characteristics due to the network hop
				//   to the passthrough target.
				//
				// - Application-level socket operations may produce detectable
				//   differences (e.g., CloseWrite/FIN).
				//
				// - The dial to the passthrough, or other upstream network operations,
				//   may fail. These errors are not logged.
				//
				// - There's no timeout on the passthrough dial and no time limit on the
				//   passthrough relay so that the invalid client can't detect a timeout
				//   shorter than the passthrough target; this may cause additional load.

				defer conn.Close()

				// Remove any pre-existing deadlines to ensure the passthrough
				// is not interrupted.
				_ = conn.SetDeadline(time.Time{})

				passthroughConn, err := net.Dial("tcp", c.config.PassthroughAddress)
				if err != nil {
					return
				}
				defer passthroughConn.Close()

				_, err = passthroughConn.Write(passthroughReadBuffer)
				if err != nil {
					return
				}

				// Allow garbage collection.
				passthroughReadBuffer = nil

				go func() {
					_, _ = io.Copy(passthroughConn, conn)
				}()
				_, _ = io.Copy(conn, passthroughConn)
			}()

		}
	}

	if err != nil {
		return err
	}

	// For an overview of TLS handshaking, see https://tools.ietf.org/html/rfc5246#section-7.3
	// and https://tools.ietf.org/html/draft-ietf-tls-tls13-18#section-2
	c.buffering = true
	if c.vers >= VersionTLS13 {
		if err := hs.doTLS13Handshake(); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.hs = &hs
		// If the client is sending early data while the server expects
		// it, delay the Finished check until HandshakeConfirmed() is
		// called or until all early data is Read(). Otherwise, complete
		// authenticating the client now (there is no support for
		// sending 0.5-RTT data to a potential unauthenticated client).
		if c.phase != readingEarlyData {
			if err := hs.readClientFinished13(false); err != nil {
				return err
			}
		}
		atomic.StoreUint32(&c.handshakeStatus, 1)
		return nil
	} else if isResume {
		// The client has included a session ticket and so we do an abbreviated handshake.
		if err := hs.doResumeHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		// ticketSupported is set in a resumption handshake if the
		// ticket from the client was encrypted with an old session
		// ticket key and thus a refreshed ticket should be sent.
		if hs.hello.ticketSupported {
			if err := hs.sendSessionTicket(); err != nil {
				return err
			}
		}
		if err := hs.sendFinished(c.serverFinished[:]); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
		c.clientFinishedIsFirst = false
		if err := hs.readFinished(nil); err != nil {
			return err
		}
		c.didResume = true
	} else {
		// The client didn't include a session ticket, or it wasn't
		// valid so we do a full handshake.
		if err := hs.doFullHandshake(); err != nil {
			return err
		}
		if err := hs.establishKeys(); err != nil {
			return err
		}
		if err := hs.readFinished(c.clientFinished[:]); err != nil {
			return err
		}
		c.clientFinishedIsFirst = true
		c.buffering = true
		if err := hs.sendSessionTicket(); err != nil {
			return err
		}
		if err := hs.sendFinished(nil); err != nil {
			return err
		}
		if _, err := c.flush(); err != nil {
			return err
		}
	}
	if c.hand.Len() > 0 {
		return c.sendAlert(alertUnexpectedMessage)
	}
	c.phase = handshakeConfirmed
	atomic.StoreInt32(&c.handshakeConfirmed, 1)

	// [Psiphon]
	// https://github.com/golang/go/commit/e5b13401c6b19f58a8439f1019a80fe540c0c687
	atomic.StoreUint32(&c.handshakeStatus, 1)

	return nil
}

// [Psiphon]
// recorderConn is a net.Conn which records all bytes read from the wrapped
// conn until GetReadBuffer is called, which returns the buffered bytes and
// stops recording. This is used to replay, byte-for-byte, the bytes sent by a
// client when switching to passthrough.
//
// recorderConn operations are not safe for concurrent use and intended only
// to be used in the initial phase of the TLS handshake, where the order of
// operations is deterministic.
type recorderConn struct {
	net.Conn
	readBuffer *bytes.Buffer
}

func newRecorderConn(conn net.Conn) *recorderConn {
	return &recorderConn{
		Conn:       conn,
		readBuffer: new(bytes.Buffer),
	}
}

func (c *recorderConn) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if n > 0 && c.readBuffer != nil {
		_, _ = c.readBuffer.Write(p[:n])
	}
	return n, err
}

func (c *recorderConn) GetReadBuffer() *bytes.Buffer {
	b := c.readBuffer
	c.readBuffer = nil
	return b
}

func (c *recorderConn) IsRecording() bool {
	return c.readBuffer != nil
}

// [Psiphon]
// closedConn is a net.Conn which behaves as if it were closed: all reads and
// writes fail. This is used when switching to passthrough mode: ownership of
// the invalid client conn is taken by the passthrough relay and a closedConn
// replaces the network conn used by the local TLS server code path.
type closedConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
}

var closedClosedError = errors.New("closed")

func newClosedConn(conn net.Conn) *closedConn {
	return &closedConn{
		localAddr:  conn.LocalAddr(),
		remoteAddr: conn.RemoteAddr(),
	}
}

func (c *closedConn) Read(_ []byte) (int, error) {
	return 0, closedClosedError
}

func (c *closedConn) Write(_ []byte) (int, error) {
	return 0, closedClosedError
}

func (c *closedConn) Close() error {
	return nil
}

func (c *closedConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *closedConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *closedConn) SetDeadline(_ time.Time) error {
	return closedClosedError
}

func (c *closedConn) SetReadDeadline(_ time.Time) error {
	return closedClosedError
}

func (c *closedConn) SetWriteDeadline(_ time.Time) error {
	return closedClosedError
}

// readClientHello reads a ClientHello message from the client and decides
// whether we will perform session resumption.
func (hs *serverHandshakeState) readClientHello() (isResume bool, err error) {
	c := hs.c

	msg, err := c.readHandshake()
	if err != nil {
		return false, err
	}
	var ok bool
	hs.clientHello, ok = msg.(*clientHelloMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return false, unexpectedMessageError(hs.clientHello, msg)
	}

	if c.config.GetConfigForClient != nil {
		if newConfig, err := c.config.GetConfigForClient(hs.clientHelloInfo()); err != nil {
			c.out.traceErr, c.in.traceErr = nil, nil // disable tracing
			c.sendAlert(alertInternalError)
			return false, err
		} else if newConfig != nil {
			newConfig.serverInitOnce.Do(func() { newConfig.serverInit(c.config) })
			c.config = newConfig
		}
	}

	var keyShares []CurveID
	for _, ks := range hs.clientHello.keyShares {
		keyShares = append(keyShares, ks.group)
	}

	if hs.clientHello.supportedVersions != nil {
		c.vers, ok = c.config.pickVersion(hs.clientHello.supportedVersions)
		if !ok {
			c.sendAlert(alertProtocolVersion)
			return false, fmt.Errorf("tls: none of the client versions (%x) are supported", hs.clientHello.supportedVersions)
		}
	} else {
		c.vers, ok = c.config.mutualVersion(hs.clientHello.vers)
		if !ok {
			c.sendAlert(alertProtocolVersion)
			return false, fmt.Errorf("tls: client offered an unsupported, maximum protocol version of %x", hs.clientHello.vers)
		}
	}
	c.haveVers = true

	preferredCurves := c.config.curvePreferences()
Curves:
	for _, curve := range hs.clientHello.supportedCurves {
		for _, supported := range preferredCurves {
			if supported == curve {
				hs.ellipticOk = true
				break Curves
			}
		}
	}

	// [Psiphon]
	hasSupportedPoints := false

	// If present, the supported points extension must include uncompressed.
	// Can be absent. This behavior mirrors BoringSSL.
	if hs.clientHello.supportedPoints != nil {
		supportedPointFormat := false
		for _, pointFormat := range hs.clientHello.supportedPoints {
			if pointFormat == pointFormatUncompressed {
				supportedPointFormat = true
				break
			}
		}
		if !supportedPointFormat {
			c.sendAlert(alertHandshakeFailure)
			return false, errors.New("tls: client does not support uncompressed points")
		}
		hasSupportedPoints = true
	}

	foundCompression := false
	// We only support null compression, so check that the client offered it.
	for _, compression := range hs.clientHello.compressionMethods {
		if compression == compressionNone {
			foundCompression = true
			break
		}
	}

	if !foundCompression {
		c.sendAlert(alertIllegalParameter)
		return false, errors.New("tls: client does not support uncompressed connections")
	}
	if len(hs.clientHello.compressionMethods) != 1 && c.vers >= VersionTLS13 {
		c.sendAlert(alertIllegalParameter)
		return false, errors.New("tls: 1.3 client offered compression")
	}

	if len(hs.clientHello.secureRenegotiation) != 0 {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: initial handshake had non-empty renegotiation extension")
	}

	if c.vers < VersionTLS13 {
		hs.hello = new(serverHelloMsg)
		hs.hello.vers = c.vers
		hs.hello.random = make([]byte, 32)
		_, err = io.ReadFull(c.config.rand(), hs.hello.random)
		if err != nil {
			c.sendAlert(alertInternalError)
			return false, err
		}
		hs.hello.secureRenegotiationSupported = hs.clientHello.secureRenegotiationSupported
		hs.hello.compressionMethod = compressionNone
	} else {
		hs.hello = new(serverHelloMsg)
		hs.hello13Enc = new(encryptedExtensionsMsg)
		hs.hello.vers = c.vers
		hs.hello.random = make([]byte, 32)
		hs.hello.sessionId = hs.clientHello.sessionId
		_, err = io.ReadFull(c.config.rand(), hs.hello.random)
		if err != nil {
			c.sendAlert(alertInternalError)
			return false, err
		}
	}

	// [Psiphon]
	// https://github.com/golang/go/commit/02a5502ab8d862309aaec3c5ec293b57b913d01d
	if hasSupportedPoints && c.vers < VersionTLS13 {
		// Although omitting the ec_point_formats extension is permitted, some
		// old OpenSSL versions will refuse to handshake if not present.
		//
		// Per RFC 4492, section 5.1.2, implementations MUST support the
		// uncompressed point format. See golang.org/issue/31943.
		hs.hello.supportedPoints = []uint8{pointFormatUncompressed}
	}

	if len(hs.clientHello.serverName) > 0 {
		c.serverName = hs.clientHello.serverName
	}

	if len(hs.clientHello.alpnProtocols) > 0 {
		if selectedProto, fallback := mutualProtocol(hs.clientHello.alpnProtocols, c.config.NextProtos); !fallback {
			if hs.hello13Enc != nil {
				hs.hello13Enc.alpnProtocol = selectedProto
			} else {
				hs.hello.alpnProtocol = selectedProto
			}
			c.clientProtocol = selectedProto
		}
	} else {
		// Although sending an empty NPN extension is reasonable, Firefox has
		// had a bug around this. Best to send nothing at all if
		// c.config.NextProtos is empty. See
		// https://golang.org/issue/5445.
		if hs.clientHello.nextProtoNeg && len(c.config.NextProtos) > 0 && c.vers < VersionTLS13 {
			hs.hello.nextProtoNeg = true
			hs.hello.nextProtos = c.config.NextProtos
		}
	}

	hs.cert, err = c.config.getCertificate(hs.clientHelloInfo())
	if err != nil {
		c.sendAlert(alertInternalError)
		return false, err
	}

	// Set the private key for this handshake to the certificate's secret key.
	hs.privateKey = hs.cert.PrivateKey

	if hs.clientHello.scts {
		hs.hello.scts = hs.cert.SignedCertificateTimestamps
	}

	// Set the private key to the DC private key if the client and server are
	// willing to negotiate the delegated credential extension.
	//
	// Check to see if a DelegatedCredential is available and should be used.
	// If one is available, the session is using TLS >= 1.2, and the client
	// accepts the delegated credential extension, then set the handshake
	// private key to the DC private key.
	if c.config.GetDelegatedCredential != nil && hs.clientHello.delegatedCredential && c.vers >= VersionTLS12 {
		dc, sk, err := c.config.GetDelegatedCredential(hs.clientHelloInfo(), c.vers)
		if err != nil {
			c.sendAlert(alertInternalError)
			return false, err
		}

		// Set the handshake private key.
		if dc != nil {
			hs.privateKey = sk
			hs.delegatedCredential = dc
		}
	}

	if priv, ok := hs.privateKey.(crypto.Signer); ok {
		switch priv.Public().(type) {
		case *ecdsa.PublicKey:
			hs.ecdsaOk = true
		case *rsa.PublicKey:
			hs.rsaSignOk = true
		default:
			c.sendAlert(alertInternalError)
			return false, fmt.Errorf("tls: unsupported signing key type (%T)", priv.Public())
		}
	}
	if priv, ok := hs.privateKey.(crypto.Decrypter); ok {
		switch priv.Public().(type) {
		case *rsa.PublicKey:
			hs.rsaDecryptOk = true
		default:
			c.sendAlert(alertInternalError)
			return false, fmt.Errorf("tls: unsupported decryption key type (%T)", priv.Public())
		}
	}

	if c.vers != VersionTLS13 && hs.checkForResumption() {
		return true, nil
	}

	var preferenceList, supportedList []uint16
	if c.config.PreferServerCipherSuites {
		preferenceList = c.config.cipherSuites()
		supportedList = hs.clientHello.cipherSuites
	} else {
		preferenceList = hs.clientHello.cipherSuites
		supportedList = c.config.cipherSuites()
	}

	for _, id := range preferenceList {
		if hs.setCipherSuite(id, supportedList, c.vers) {
			break
		}
	}

	if hs.suite == nil {
		c.sendAlert(alertHandshakeFailure)
		return false, errors.New("tls: no cipher suite supported by both client and server")
	}

	// See https://tools.ietf.org/html/rfc7507.
	for _, id := range hs.clientHello.cipherSuites {
		if id == TLS_FALLBACK_SCSV {
			// The client is doing a fallback connection.
			if c.vers < c.config.maxVersion() {
				c.sendAlert(alertInappropriateFallback)
				return false, errors.New("tls: client using inappropriate protocol fallback")
			}
			break
		}
	}

	return false, nil
}

// checkForResumption reports whether we should perform resumption on this connection.
func (hs *serverHandshakeState) checkForResumption() bool {
	c := hs.c

	if c.config.SessionTicketsDisabled {
		return false
	}

	sessionTicket := append([]uint8{}, hs.clientHello.sessionTicket...)
	serializedState, usedOldKey := c.decryptTicket(sessionTicket)
	hs.sessionState = &sessionState{usedOldKey: usedOldKey}
	if hs.sessionState.unmarshal(serializedState) != alertSuccess {
		return false
	}

	// Never resume a session for a different TLS version.
	if c.vers != hs.sessionState.vers {
		return false
	}

	// [Psiphon]
	// When using obfuscated session tickets, the client-generated session ticket
	// state never uses EMS. ClientHellos vary in EMS support. So, in this mode,
	// skip this check to ensure the obfuscated session tickets are not
	// rejected.
	if !c.config.UseObfuscatedSessionTickets {

		// Do not resume connections where client support for EMS has changed
		if (hs.clientHello.extendedMSSupported && c.config.UseExtendedMasterSecret) != hs.sessionState.usedEMS {
			return false
		}
	}

	cipherSuiteOk := false
	// Check that the client is still offering the ciphersuite in the session.
	for _, id := range hs.clientHello.cipherSuites {
		if id == hs.sessionState.cipherSuite {
			cipherSuiteOk = true
			break
		}
	}
	if !cipherSuiteOk {
		return false
	}

	// Check that we also support the ciphersuite from the session.
	if !hs.setCipherSuite(hs.sessionState.cipherSuite, c.config.cipherSuites(), hs.sessionState.vers) {
		return false
	}

	sessionHasClientCerts := len(hs.sessionState.certificates) != 0
	needClientCerts := c.config.ClientAuth == RequireAnyClientCert || c.config.ClientAuth == RequireAndVerifyClientCert
	if needClientCerts && !sessionHasClientCerts {
		return false
	}
	if sessionHasClientCerts && c.config.ClientAuth == NoClientCert {
		return false
	}

	return true
}

func (hs *serverHandshakeState) doResumeHandshake() error {
	c := hs.c

	hs.hello.cipherSuite = hs.suite.id
	// We echo the client's session ID in the ServerHello to let it know
	// that we're doing a resumption.
	hs.hello.sessionId = hs.clientHello.sessionId
	hs.hello.ticketSupported = hs.sessionState.usedOldKey
	hs.hello.extendedMSSupported = hs.clientHello.extendedMSSupported && c.config.UseExtendedMasterSecret
	hs.finishedHash = newFinishedHash(c.vers, hs.suite)
	hs.finishedHash.discardHandshakeBuffer()
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	if len(hs.sessionState.certificates) > 0 {
		if _, err := hs.processCertsFromClient(hs.sessionState.certificates); err != nil {
			return err
		}
	}

	hs.masterSecret = hs.sessionState.masterSecret
	c.useEMS = hs.sessionState.usedEMS

	return nil
}

func (hs *serverHandshakeState) doFullHandshake() error {
	c := hs.c

	if hs.clientHello.ocspStapling && len(hs.cert.OCSPStaple) > 0 {
		hs.hello.ocspStapling = true
	}

	hs.hello.ticketSupported = hs.clientHello.ticketSupported && !c.config.SessionTicketsDisabled
	hs.hello.cipherSuite = hs.suite.id
	hs.hello.extendedMSSupported = hs.clientHello.extendedMSSupported && c.config.UseExtendedMasterSecret

	hs.finishedHash = newFinishedHash(hs.c.vers, hs.suite)
	if c.config.ClientAuth == NoClientCert {
		// No need to keep a full record of the handshake if client
		// certificates won't be used.
		hs.finishedHash.discardHandshakeBuffer()
	}
	hs.finishedHash.Write(hs.clientHello.marshal())
	hs.finishedHash.Write(hs.hello.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, hs.hello.marshal()); err != nil {
		return err
	}

	certMsg := new(certificateMsg)
	certMsg.certificates = hs.cert.Certificate
	hs.finishedHash.Write(certMsg.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, certMsg.marshal()); err != nil {
		return err
	}

	if hs.hello.ocspStapling {
		certStatus := new(certificateStatusMsg)
		certStatus.statusType = statusTypeOCSP
		certStatus.response = hs.cert.OCSPStaple
		hs.finishedHash.Write(certStatus.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certStatus.marshal()); err != nil {
			return err
		}
	}

	keyAgreement := hs.suite.ka(c.vers)
	skx, err := keyAgreement.generateServerKeyExchange(c.config, hs.privateKey, hs.clientHello, hs.hello)
	if err != nil {
		c.sendAlert(alertHandshakeFailure)
		return err
	}
	if skx != nil {
		hs.finishedHash.Write(skx.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, skx.marshal()); err != nil {
			return err
		}
	}

	if c.config.ClientAuth >= RequestClientCert {
		// Request a client certificate
		certReq := new(certificateRequestMsg)
		certReq.certificateTypes = []byte{
			byte(certTypeRSASign),
			byte(certTypeECDSASign),
		}
		if c.vers >= VersionTLS12 {
			certReq.hasSignatureAndHash = true
			certReq.supportedSignatureAlgorithms = supportedSignatureAlgorithms
		}

		// An empty list of certificateAuthorities signals to
		// the client that it may send any certificate in response
		// to our request. When we know the CAs we trust, then
		// we can send them down, so that the client can choose
		// an appropriate certificate to give to us.
		if c.config.ClientCAs != nil {
			certReq.certificateAuthorities = c.config.ClientCAs.Subjects()
		}
		hs.finishedHash.Write(certReq.marshal())
		if _, err := c.writeRecord(recordTypeHandshake, certReq.marshal()); err != nil {
			return err
		}
	}

	helloDone := new(serverHelloDoneMsg)
	hs.finishedHash.Write(helloDone.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, helloDone.marshal()); err != nil {
		return err
	}

	if _, err := c.flush(); err != nil {
		return err
	}

	var pub crypto.PublicKey // public key for client auth, if any

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}

	var ok bool
	// If we requested a client certificate, then the client must send a
	// certificate message, even if it's empty.
	if c.config.ClientAuth >= RequestClientCert {
		if certMsg, ok = msg.(*certificateMsg); !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certMsg, msg)
		}
		hs.finishedHash.Write(certMsg.marshal())

		if len(certMsg.certificates) == 0 {
			// The client didn't actually send a certificate
			switch c.config.ClientAuth {
			case RequireAnyClientCert, RequireAndVerifyClientCert:
				c.sendAlert(alertBadCertificate)
				return errors.New("tls: client didn't provide a certificate")
			}
		}

		pub, err = hs.processCertsFromClient(certMsg.certificates)
		if err != nil {
			return err
		}

		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
	}

	// Get client key exchange
	ckx, ok := msg.(*clientKeyExchangeMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(ckx, msg)
	}
	hs.finishedHash.Write(ckx.marshal())

	preMasterSecret, err := keyAgreement.processClientKeyExchange(c.config, hs.privateKey, ckx, c.vers)
	if err != nil {
		if err == errClientKeyExchange {
			c.sendAlert(alertDecodeError)
		} else {
			c.sendAlert(alertInternalError)
		}
		return err
	}
	c.useEMS = hs.hello.extendedMSSupported
	hs.masterSecret = masterFromPreMasterSecret(c.vers, hs.suite, preMasterSecret, hs.clientHello.random, hs.hello.random, hs.finishedHash, c.useEMS)
	if err := c.config.writeKeyLog("CLIENT_RANDOM", hs.clientHello.random, hs.masterSecret); err != nil {
		c.sendAlert(alertInternalError)
		return err
	}

	// If we received a client cert in response to our certificate request message,
	// the client will send us a certificateVerifyMsg immediately after the
	// clientKeyExchangeMsg. This message is a digest of all preceding
	// handshake-layer messages that is signed using the private key corresponding
	// to the client's certificate. This allows us to verify that the client is in
	// possession of the private key of the certificate.
	if len(c.peerCertificates) > 0 {
		msg, err = c.readHandshake()
		if err != nil {
			return err
		}
		certVerify, ok := msg.(*certificateVerifyMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(certVerify, msg)
		}

		// Determine the signature type.
		_, sigType, hashFunc, err := pickSignatureAlgorithm(pub, []SignatureScheme{certVerify.signatureAlgorithm}, supportedSignatureAlgorithms, c.vers)
		if err != nil {
			c.sendAlert(alertIllegalParameter)
			return err
		}

		var digest []byte
		if digest, err = hs.finishedHash.hashForClientCertificate(sigType, hashFunc, hs.masterSecret); err == nil {
			err = verifyHandshakeSignature(sigType, pub, hashFunc, digest, certVerify.signature)
		}
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return errors.New("tls: could not validate signature of connection nonces: " + err.Error())
		}

		hs.finishedHash.Write(certVerify.marshal())
	}

	hs.finishedHash.discardHandshakeBuffer()

	return nil
}

func (hs *serverHandshakeState) establishKeys() error {
	c := hs.c

	clientMAC, serverMAC, clientKey, serverKey, clientIV, serverIV :=
		keysFromMasterSecret(c.vers, hs.suite, hs.masterSecret, hs.clientHello.random, hs.hello.random, hs.suite.macLen, hs.suite.keyLen, hs.suite.ivLen)

	var clientCipher, serverCipher interface{}
	var clientHash, serverHash macFunction

	if hs.suite.aead == nil {
		clientCipher = hs.suite.cipher(clientKey, clientIV, true /* for reading */)
		clientHash = hs.suite.mac(c.vers, clientMAC)
		serverCipher = hs.suite.cipher(serverKey, serverIV, false /* not for reading */)
		serverHash = hs.suite.mac(c.vers, serverMAC)
	} else {
		clientCipher = hs.suite.aead(clientKey, clientIV)
		serverCipher = hs.suite.aead(serverKey, serverIV)
	}

	c.in.prepareCipherSpec(c.vers, clientCipher, clientHash)
	c.out.prepareCipherSpec(c.vers, serverCipher, serverHash)

	return nil
}

func (hs *serverHandshakeState) readFinished(out []byte) error {
	c := hs.c

	c.readRecord(recordTypeChangeCipherSpec)
	if c.in.err != nil {
		return c.in.err
	}

	if hs.hello.nextProtoNeg {
		msg, err := c.readHandshake()
		if err != nil {
			return err
		}
		nextProto, ok := msg.(*nextProtoMsg)
		if !ok {
			c.sendAlert(alertUnexpectedMessage)
			return unexpectedMessageError(nextProto, msg)
		}
		hs.finishedHash.Write(nextProto.marshal())
		c.clientProtocol = nextProto.proto
	}

	msg, err := c.readHandshake()
	if err != nil {
		return err
	}
	clientFinished, ok := msg.(*finishedMsg)
	if !ok {
		c.sendAlert(alertUnexpectedMessage)
		return unexpectedMessageError(clientFinished, msg)
	}

	verify := hs.finishedHash.clientSum(hs.masterSecret)
	if len(verify) != len(clientFinished.verifyData) ||
		subtle.ConstantTimeCompare(verify, clientFinished.verifyData) != 1 {
		c.sendAlert(alertDecryptError)
		return errors.New("tls: client's Finished message is incorrect")
	}

	hs.finishedHash.Write(clientFinished.marshal())
	copy(out, verify)
	return nil
}

func (hs *serverHandshakeState) sendSessionTicket() error {
	if !hs.hello.ticketSupported {
		return nil
	}

	c := hs.c
	m := new(newSessionTicketMsg)

	var err error
	state := sessionState{
		vers:         c.vers,
		cipherSuite:  hs.suite.id,
		masterSecret: hs.masterSecret,
		certificates: hs.certsFromClient,
		usedEMS:      c.useEMS,
	}
	m.ticket, err = c.encryptTicket(state.marshal())
	if err != nil {
		return err
	}

	hs.finishedHash.Write(m.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, m.marshal()); err != nil {
		return err
	}

	return nil
}

func (hs *serverHandshakeState) sendFinished(out []byte) error {
	c := hs.c

	if _, err := c.writeRecord(recordTypeChangeCipherSpec, []byte{1}); err != nil {
		return err
	}

	finished := new(finishedMsg)
	finished.verifyData = hs.finishedHash.serverSum(hs.masterSecret)
	hs.finishedHash.Write(finished.marshal())
	if _, err := c.writeRecord(recordTypeHandshake, finished.marshal()); err != nil {
		return err
	}

	c.cipherSuite = hs.suite.id
	copy(out, finished.verifyData)

	return nil
}

// processCertsFromClient takes a chain of client certificates either from a
// Certificates message or from a sessionState and verifies them. It returns
// the public key of the leaf certificate.
func (hs *serverHandshakeState) processCertsFromClient(certificates [][]byte) (crypto.PublicKey, error) {
	c := hs.c

	hs.certsFromClient = certificates
	certs := make([]*x509.Certificate, len(certificates))
	var err error
	for i, asn1Data := range certificates {
		if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, errors.New("tls: failed to parse client certificate: " + err.Error())
		}
	}

	if c.config.ClientAuth >= VerifyClientCertIfGiven && len(certs) > 0 {
		opts := x509.VerifyOptions{
			Roots:         c.config.ClientCAs,
			CurrentTime:   c.config.time(),
			Intermediates: x509.NewCertPool(),
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}

		for _, cert := range certs[1:] {
			opts.Intermediates.AddCert(cert)
		}

		chains, err := certs[0].Verify(opts)
		if err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, errors.New("tls: failed to verify client's certificate: " + err.Error())
		}

		c.verifiedChains = chains
	}

	if c.config.VerifyPeerCertificate != nil {
		if err := c.config.VerifyPeerCertificate(certificates, c.verifiedChains); err != nil {
			c.sendAlert(alertBadCertificate)
			return nil, err
		}
	}

	if len(certs) == 0 {
		return nil, nil
	}

	var pub crypto.PublicKey
	switch key := certs[0].PublicKey.(type) {
	case *ecdsa.PublicKey, *rsa.PublicKey:
		pub = key
	default:
		c.sendAlert(alertUnsupportedCertificate)
		return nil, fmt.Errorf("tls: client's certificate contains an unsupported public key of type %T", certs[0].PublicKey)
	}
	c.peerCertificates = certs
	return pub, nil
}

// setCipherSuite sets a cipherSuite with the given id as the serverHandshakeState
// suite if that cipher suite is acceptable to use.
// It returns a bool indicating if the suite was set.
func (hs *serverHandshakeState) setCipherSuite(id uint16, supportedCipherSuites []uint16, version uint16) bool {
	for _, supported := range supportedCipherSuites {
		if id == supported {
			var candidate *cipherSuite

			for _, s := range cipherSuites {
				if s.id == id {
					candidate = s
					break
				}
			}
			if candidate == nil {
				continue
			}

			if version >= VersionTLS13 && candidate.flags&suiteTLS13 != 0 {
				hs.suite = candidate
				return true
			}
			if version < VersionTLS13 && candidate.flags&suiteTLS13 != 0 {
				continue
			}

			// Don't select a ciphersuite which we can't
			// support for this client.
			if candidate.flags&suiteECDHE != 0 {
				if !hs.ellipticOk {
					continue
				}
				if candidate.flags&suiteECDSA != 0 {
					if !hs.ecdsaOk {
						continue
					}
				} else if !hs.rsaSignOk {
					continue
				}
			} else if !hs.rsaDecryptOk {
				continue
			}
			if version < VersionTLS12 && candidate.flags&suiteTLS12 != 0 {
				continue
			}
			hs.suite = candidate
			return true
		}
	}
	return false
}

// suppVersArray is the backing array of ClientHelloInfo.SupportedVersions
var suppVersArray = [...]uint16{VersionTLS12, VersionTLS11, VersionTLS10, VersionSSL30}

func (hs *serverHandshakeState) clientHelloInfo() *ClientHelloInfo {
	if hs.cachedClientHelloInfo != nil {
		return hs.cachedClientHelloInfo
	}

	var supportedVersions []uint16
	if hs.clientHello.supportedVersions != nil {
		supportedVersions = hs.clientHello.supportedVersions
	} else if hs.clientHello.vers > VersionTLS12 {
		supportedVersions = suppVersArray[:]
	} else if hs.clientHello.vers >= VersionSSL30 {
		supportedVersions = suppVersArray[VersionTLS12-hs.clientHello.vers:]
	}

	var pskBinder []byte
	if len(hs.clientHello.psks) > 0 {
		pskBinder = hs.clientHello.psks[0].binder
	}

	hs.cachedClientHelloInfo = &ClientHelloInfo{
		CipherSuites:               hs.clientHello.cipherSuites,
		ServerName:                 hs.clientHello.serverName,
		SupportedCurves:            hs.clientHello.supportedCurves,
		SupportedPoints:            hs.clientHello.supportedPoints,
		SignatureSchemes:           hs.clientHello.supportedSignatureAlgorithms,
		SupportedProtos:            hs.clientHello.alpnProtocols,
		SupportedVersions:          supportedVersions,
		Conn:                       hs.c.conn,
		Offered0RTTData:            hs.clientHello.earlyData,
		AcceptsDelegatedCredential: hs.clientHello.delegatedCredential,
		Fingerprint:                pskBinder,
	}

	return hs.cachedClientHelloInfo
}
