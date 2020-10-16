package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"sync/atomic"
	"log"
	"github.com/Azure/go-ntlmssp"
	"strings"
	"syscall"
	"unsafe"
)

// NtlmAuthenticator defines interface to provide methods to get byte arrays required for NTLM authentication
type NtlmAuthenticator interface {
	GetNegotiateBytes() ([]byte, error)
	GetResponseBytes([]byte) ([]byte, error)
	ReleaseContext()
}
const (
	SEC_E_OK                        = 0
	SECPKG_CRED_OUTBOUND            = 2
	SEC_WINNT_AUTH_IDENTITY_UNICODE = 2
	ISC_REQ_DELEGATE                = 0x00000001
	ISC_REQ_REPLAY_DETECT           = 0x00000004
	ISC_REQ_SEQUENCE_DETECT         = 0x00000008
	ISC_REQ_CONFIDENTIALITY         = 0x00000010
	ISC_REQ_CONNECTION              = 0x00000800
	SECURITY_NETWORK_DREP           = 0
	SEC_I_CONTINUE_NEEDED           = 0x00090312
	SEC_I_COMPLETE_NEEDED           = 0x00090313
	SEC_I_COMPLETE_AND_CONTINUE     = 0x00090314
	SECBUFFER_VERSION               = 0
	SECBUFFER_TOKEN                 = 2
	NTLMBUF_LEN                     = 12000
)

const ISC_REQ = ISC_REQ_CONFIDENTIALITY |
	ISC_REQ_REPLAY_DETECT |
	ISC_REQ_SEQUENCE_DETECT |
	ISC_REQ_CONNECTION |
	ISC_REQ_DELEGATE

type SecurityFunctionTable struct {
	dwVersion                  uint32
	EnumerateSecurityPackages  uintptr
	QueryCredentialsAttributes uintptr
	AcquireCredentialsHandle   uintptr
	FreeCredentialsHandle      uintptr
	Reserved2                  uintptr
	InitializeSecurityContext  uintptr
	AcceptSecurityContext      uintptr
	CompleteAuthToken          uintptr
	DeleteSecurityContext      uintptr
	ApplyControlToken          uintptr
	QueryContextAttributes     uintptr
	ImpersonateSecurityContext uintptr
	RevertSecurityContext      uintptr
	MakeSignature              uintptr
	VerifySignature            uintptr
	FreeContextBuffer          uintptr
	QuerySecurityPackageInfo   uintptr
	Reserved3                  uintptr
	Reserved4                  uintptr
	Reserved5                  uintptr
	Reserved6                  uintptr
	Reserved7                  uintptr
	Reserved8                  uintptr
	QuerySecurityContextToken  uintptr
	EncryptMessage             uintptr
	DecryptMessage             uintptr
}

type SEC_WINNT_AUTH_IDENTITY struct {
	User           *uint16
	UserLength     uint32
	Domain         *uint16
	DomainLength   uint32
	Password       *uint16
	PasswordLength uint32
	Flags          uint32
}

type TimeStamp struct {
	LowPart  uint32
	HighPart int32
}

type SecHandle struct {
	dwLower uintptr
	dwUpper uintptr
}

type SecBuffer struct {
	cbBuffer   uint32
	BufferType uint32
	pvBuffer   *byte
}

type SecBufferDesc struct {
	ulVersion uint32
	cBuffers  uint32
	pBuffers  *SecBuffer
}

type SSPIAuth struct {
	Domain   string
	UserName string
	Password string
	Service  string
	cred     SecHandle
	ctxt     SecHandle
}

var (
	initialized = false
	sec_fn *SecurityFunctionTable
)

func initialize() {
	
	secur32dll            := syscall.NewLazyDLL("secur32.dll")
	initSecurityInterface := secur32dll.NewProc("InitSecurityInterfaceW")
		
	ptr, _, _ := initSecurityInterface.Call()
	sec_fn = (*SecurityFunctionTable)(unsafe.Pointer(ptr))
	
	initialized = true
}

func main(){

    executeMain(os.Args[1], os.Args[2], os.Args[3])

}

func getReq(_url string, _user string, _password string) *http.Request {
    req, err := http.NewRequest("GET", _url, nil)
    req.SetBasicAuth(_user, _password)
    fmt.Println(err)
    return req
}

func executeMain(_url string, _user string, _pass string) {

    url_, user_, password_ := _url, _user, _pass
    fmt.Println("Url..............:" + url_)
    fmt.Println("Dominio e Usuario:" + user_)
    fmt.Println("Senha............:" + password_)

    fmt.Println("")

    fmt.Println("Instanciando o objeto Client:")
    client := &http.Client{
        Transport: ntlmssp.Negotiator{
            RoundTripper:&http.Transport{},
        },
    }

    fmt.Println("Atribuindo variáveis:")
    req := getReq(url_, user_, password_)

	
    fmt.Println("Efetuando Request:")
    resp, err := DoNTLMRequest(client, req)
    resolvData(err, resp)
}

func resolvData(_err error, _resp *http.Response) {
    if _err != nil {
        fmt.Printf("Erro : %s", _err)
    } else {
        responseData, _err := ioutil.ReadAll(_resp.Body)
        if _err != nil {
            log.Fatal(_err)
        }
        if _resp.StatusCode >= 200 && _resp.StatusCode <= 299 {
            fmt.Println("OK 200: ", _resp.StatusCode)
        } else {
            fmt.Println("Err <> 200: ", _resp.StatusCode)
        }
        responseString := string(responseData)
        fmt.Println(responseString)
        _resp.Body.Close()
    }    
}


// DoNTLMRequest Perform a request using NTLM authentication
func DoNTLMRequest(httpClient *http.Client, request *http.Request) (*http.Response, error) {

	handshakeReq, err := cloneRequest(request)
	if err != nil {
		return nil, err
	}

	res, err := httpClient.Do(handshakeReq)
	if err != nil && res == nil {
		return nil, err
	}

	//If the status is 401 then we need to re-authenticate, otherwise it was successful
	if res.StatusCode == 401 {

		auth, authOk := getDefaultCredentialsAuth()
		if authOk {
			negotiateMessageBytes, err := auth.GetNegotiateBytes()
			if err != nil {
				return nil, err
			}
			defer auth.ReleaseContext()

			negotiateReq, err := cloneRequest(request)
			if err != nil {
				return nil, err
			}

			challengeMessage, err := sendNegotiateRequest(httpClient, negotiateReq, negotiateMessageBytes)
			if err != nil {
				return nil, err
			}

			challengeReq, err := cloneRequest(request)
			if err != nil {
				return nil, err
			}

			responseBytes, err := auth.GetResponseBytes(challengeMessage)

			res, err := sendChallengeRequest(httpClient, challengeReq, responseBytes)
			if err != nil {
				return nil, err
			}

			return res, nil
		}
	}

	return res, nil
}

func sendNegotiateRequest(httpClient *http.Client, request *http.Request, negotiateMessageBytes []byte) ([]byte, error) {
	negotiateMsg := base64.StdEncoding.EncodeToString(negotiateMessageBytes)

	request.Header.Add("Authorization", "NTLM "+negotiateMsg)
	res, err := httpClient.Do(request)

	if res == nil && err != nil {
		return nil, err
	}

	io.Copy(ioutil.Discard, res.Body)
	res.Body.Close()

	ret, err := parseChallengeResponse(res)
	if err != nil {
		return nil, err
	}

	return ret, nil
}

func sendChallengeRequest(httpClient *http.Client, request *http.Request, challengeBytes []byte) (*http.Response, error) {
	authMsg := base64.StdEncoding.EncodeToString(challengeBytes)
	request.Header.Add("Authorization", "NTLM "+authMsg)
	return httpClient.Do(request)
}

func parseChallengeResponse(response *http.Response) ([]byte, error) {
	header := response.Header.Get("Www-Authenticate")
	if len(header) < 6 {
		return nil, fmt.Errorf("Invalid NTLM challenge response: %q", header)
	}

	//parse out the "NTLM " at the beginning of the response
	challenge := header[5:]
	val, err := base64.StdEncoding.DecodeString(challenge)

	if err != nil {
		return nil, err
	}
	return []byte(val), nil
}

func cloneRequest(request *http.Request) (*http.Request, error) {
	cloneReqBody, err := cloneRequestBody(request)
	if err != nil {
		return nil, err
	}

	clonedReq, err := http.NewRequest(request.Method, request.URL.String(), cloneReqBody)
	if err != nil {
		return nil, err
	}

	for k := range request.Header {
		clonedReq.Header.Add(k, request.Header.Get(k))
	}

	clonedReq.TransferEncoding = request.TransferEncoding
	clonedReq.ContentLength = request.ContentLength

	return clonedReq, nil
}

func cloneRequestBody(req *http.Request) (io.ReadCloser, error) {
	if req.Body == nil {
		return nil, nil
	}

	var cb *cloneableBody
	var err error
	isCloneableBody := true

	// check to see if the request body is already a cloneableBody
	body := req.Body
	if existingCb, ok := body.(*cloneableBody); ok {
		isCloneableBody = false
		cb, err = existingCb.CloneBody()
	} else {
		cb, err = newCloneableBody(req.Body, 0)
	}

	if err != nil {
		return nil, err
	}

	if isCloneableBody {
		cb2, err := cb.CloneBody()
		if err != nil {
			return nil, err
		}

		req.Body = cb2
	}

	return cb, nil
}

type cloneableBody struct {
	bytes  []byte    // in-memory buffer of body
	file   *os.File  // file buffer of in-memory overflow
	reader io.Reader // internal reader for Read()
	closed bool      // tracks whether body is closed
	dup    *dupTracker
}

func newCloneableBody(r io.Reader, limit int64) (*cloneableBody, error) {
	if limit < 1 {
		limit = 1048576 // default
	}

	b := &cloneableBody{}
	buf := &bytes.Buffer{}
	w, err := io.CopyN(buf, r, limit)
	if err != nil && err != io.EOF {
		return nil, err
	}

	b.bytes = buf.Bytes()
	byReader := bytes.NewBuffer(b.bytes)

	if w >= limit {
		tmp, err := ioutil.TempFile("", "git-lfs-clone-reader")
		if err != nil {
			return nil, err
		}

		_, err = io.Copy(tmp, r)
		tmp.Close()
		if err != nil {
			os.RemoveAll(tmp.Name())
			return nil, err
		}

		f, err := os.Open(tmp.Name())
		if err != nil {
			os.RemoveAll(tmp.Name())
			return nil, err
		}

		dups := int32(0)
		b.dup = &dupTracker{name: f.Name(), dups: &dups}
		b.file = f
		b.reader = io.MultiReader(byReader, b.file)
	} else {
		// no file, so set the reader to just the in-memory buffer
		b.reader = byReader
	}

	return b, nil
}

func (b *cloneableBody) Read(p []byte) (int, error) {
	if b.closed {
		return 0, io.EOF
	}
	return b.reader.Read(p)
}

func (b *cloneableBody) Close() error {
	if !b.closed {
		b.closed = true
		if b.file == nil {
			return nil
		}

		b.file.Close()
		b.dup.Rm()
	}
	return nil
}

func (b *cloneableBody) CloneBody() (*cloneableBody, error) {
	if b.closed {
		return &cloneableBody{closed: true}, nil
	}

	b2 := &cloneableBody{bytes: b.bytes}

	if b.file == nil {
		b2.reader = bytes.NewBuffer(b.bytes)
	} else {
		f, err := os.Open(b.file.Name())
		if err != nil {
			return nil, err
		}
		b2.file = f
		b2.reader = io.MultiReader(bytes.NewBuffer(b.bytes), b2.file)
		b2.dup = b.dup
		b.dup.Add()
	}

	return b2, nil
}

type dupTracker struct {
	name string
	dups *int32
}

func (t *dupTracker) Add() {
	atomic.AddInt32(t.dups, 1)
}

func (t *dupTracker) Rm() {
	newval := atomic.AddInt32(t.dups, -1)
	if newval < 0 {
		os.RemoveAll(t.name)
	}
}

func getDefaultCredentialsAuth() (NtlmAuthenticator, bool) {
	return getAuth("", "", "", "")
}

func getAuth(user, password, service, workstation string) (NtlmAuthenticator, bool) {
	if !initialized {
		initialize()
	}
	
	if user == "" {
		return &SSPIAuth{Service: service}, true
	}
	if !strings.ContainsRune(user, '\\') {
		return nil, false
	}
	domain_user := strings.SplitN(user, "\\", 2)
	return &SSPIAuth{
		Domain:   domain_user[0],
		UserName: domain_user[1],
		Password: password,
		Service:  service,
	}, true
}

func (auth *SSPIAuth) GetNegotiateBytes() ([]byte, error) {
	var identity *SEC_WINNT_AUTH_IDENTITY
	if auth.UserName != "" {
		identity = &SEC_WINNT_AUTH_IDENTITY{
			Flags:          SEC_WINNT_AUTH_IDENTITY_UNICODE,
			Password:       syscall.StringToUTF16Ptr(auth.Password),
			PasswordLength: uint32(len(auth.Password)),
			Domain:         syscall.StringToUTF16Ptr(auth.Domain),
			DomainLength:   uint32(len(auth.Domain)),
			User:           syscall.StringToUTF16Ptr(auth.UserName),
			UserLength:     uint32(len(auth.UserName)),
		}
	}
	var ts TimeStamp
	sec_ok, _, _ := syscall.Syscall9(sec_fn.AcquireCredentialsHandle,
		9,
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr("NTLM"))), //'NTLM' or 'Negotiate' for Kerberos
		SECPKG_CRED_OUTBOUND,
		0,
		uintptr(unsafe.Pointer(identity)),
		0,
		0,
		uintptr(unsafe.Pointer(&auth.cred)),
		uintptr(unsafe.Pointer(&ts)))
	if sec_ok != SEC_E_OK {
		return nil, fmt.Errorf("AcquireCredentialsHandle failed %x", sec_ok)
	}

	var buf SecBuffer
	var desc SecBufferDesc
	desc.ulVersion = SECBUFFER_VERSION
	desc.cBuffers = 1
	desc.pBuffers = &buf

	outbuf := make([]byte, NTLMBUF_LEN)
	buf.cbBuffer = NTLMBUF_LEN
	buf.BufferType = SECBUFFER_TOKEN
	buf.pvBuffer = &outbuf[0]

	var attrs uint32
	sec_ok, _, _ = syscall.Syscall12(sec_fn.InitializeSecurityContext,
		12,
		uintptr(unsafe.Pointer(&auth.cred)),
		0,
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(auth.Service))),
		ISC_REQ,
		0,
		SECURITY_NETWORK_DREP,
		0,
		0,
		uintptr(unsafe.Pointer(&auth.ctxt)),
		uintptr(unsafe.Pointer(&desc)),
		uintptr(unsafe.Pointer(&attrs)),
		uintptr(unsafe.Pointer(&ts)))
	if sec_ok == SEC_I_COMPLETE_AND_CONTINUE ||
		sec_ok == SEC_I_COMPLETE_NEEDED {
		syscall.Syscall6(sec_fn.CompleteAuthToken,
			2,
			uintptr(unsafe.Pointer(&auth.ctxt)),
			uintptr(unsafe.Pointer(&desc)),
			0, 0, 0, 0)
	} else if sec_ok != SEC_E_OK &&
		sec_ok != SEC_I_CONTINUE_NEEDED {
		syscall.Syscall6(sec_fn.FreeCredentialsHandle,
			1,
			uintptr(unsafe.Pointer(&auth.cred)),
			0, 0, 0, 0, 0)
		return nil, fmt.Errorf("InitialBytes InitializeSecurityContext failed %x", sec_ok)
	}
	return outbuf[:buf.cbBuffer], nil
}

func (auth *SSPIAuth) GetResponseBytes(bytes []byte) ([]byte, error) {
	var in_buf, out_buf SecBuffer
	var in_desc, out_desc SecBufferDesc

	in_desc.ulVersion = SECBUFFER_VERSION
	in_desc.cBuffers = 1
	in_desc.pBuffers = &in_buf

	out_desc.ulVersion = SECBUFFER_VERSION
	out_desc.cBuffers = 1
	out_desc.pBuffers = &out_buf

	in_buf.BufferType = SECBUFFER_TOKEN
	in_buf.pvBuffer = &bytes[0]
	in_buf.cbBuffer = uint32(len(bytes))

	outbuf := make([]byte, NTLMBUF_LEN)
	out_buf.BufferType = SECBUFFER_TOKEN
	out_buf.pvBuffer = &outbuf[0]
	out_buf.cbBuffer = NTLMBUF_LEN

	var attrs uint32
	var ts TimeStamp
	sec_ok, _, _ := syscall.Syscall12(sec_fn.InitializeSecurityContext,
		12,
		uintptr(unsafe.Pointer(&auth.cred)),
		uintptr(unsafe.Pointer(&auth.ctxt)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(auth.Service))),
		ISC_REQ,
		0,
		SECURITY_NETWORK_DREP,
		uintptr(unsafe.Pointer(&in_desc)),
		0,
		uintptr(unsafe.Pointer(&auth.ctxt)),
		uintptr(unsafe.Pointer(&out_desc)),
		uintptr(unsafe.Pointer(&attrs)),
		uintptr(unsafe.Pointer(&ts)))
	if sec_ok == SEC_I_COMPLETE_AND_CONTINUE ||
		sec_ok == SEC_I_COMPLETE_NEEDED {
		syscall.Syscall6(sec_fn.CompleteAuthToken,
			2,
			uintptr(unsafe.Pointer(&auth.ctxt)),
			uintptr(unsafe.Pointer(&out_desc)),
			0, 0, 0, 0)
	} else if sec_ok != SEC_E_OK &&
		sec_ok != SEC_I_CONTINUE_NEEDED {
		return nil, fmt.Errorf("NextBytes InitializeSecurityContext failed %x", sec_ok)
	}

	return outbuf[:out_buf.cbBuffer], nil
}

func (auth *SSPIAuth) ReleaseContext() {
	syscall.Syscall6(sec_fn.DeleteSecurityContext,
		1,
		uintptr(unsafe.Pointer(&auth.ctxt)),
		0, 0, 0, 0, 0)
	syscall.Syscall6(sec_fn.FreeCredentialsHandle,
		1,
		uintptr(unsafe.Pointer(&auth.cred)),
		0, 0, 0, 0, 0)
}
