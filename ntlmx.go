
package main

import (
	"bytes"
	"encoding/base64"
	"flag"
	"io"
	"io/ioutil"
	"net/http"
	"strings"
	"log"

        "github.com/koltyakov/gosip"
        strategy "github.com/koltyakov/gosip/auth/ntlm"
        httpntlm "github.com/vadimi/go-http-ntlm"

	ntlmssp "github.com/Azure/go-ntlmssp"
)

type Negotiator struct{ http.RoundTripper }

func (l Negotiator) RoundTrip(req *http.Request) (res *http.Response, err error) {
	rt := l.RoundTripper
	if rt == nil {
		rt = http.DefaultTransport
	}

	reqauth := authheader(req.Header.Get("Authorization"))
	if !reqauth.IsBasic() {
		return rt.RoundTrip(req)
	}
	// Save request body
	body := bytes.Buffer{}
	if req.Body != nil {
		_, err = body.ReadFrom(req.Body)
		if err != nil {
			return nil, err
		}

		req.Body.Close()
		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))
	}
	// first try anonymous, in case the server still finds us
	// authenticated from previous traffic
	req.Header.Del("Authorization")
	res, err = rt.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != http.StatusUnauthorized {
		return res, err
	}

	resauth := authheader(strings.Join(res.Header["Www-Authenticate"], " "))
	if !resauth.IsNegotiate() && !resauth.IsNTLM() {
		// Unauthorized, Negotiate not requested, let's try with basic auth
		req.Header.Set("Authorization", string(reqauth))
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()
		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

		res, err = rt.RoundTrip(req)
		if err != nil {
			return nil, err
		}
		if res.StatusCode != http.StatusUnauthorized {
			return res, err
		}
		resauth = authheader(strings.Join(res.Header["Www-Authenticate"], " "))
	}

	if resauth.IsNegotiate() || resauth.IsNTLM() {
		// 401 with request:Basic and response:Negotiate
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()

		// recycle credentials
		u, p, err := reqauth.GetBasicCreds()
		if err != nil {
			return nil, err
		}

		// get domain from username
		domain := ""
		u, domain = ntlmssp.GetDomain(u)
		// send negotiate
		negotiateMessage, err := ntlmssp.NewNegotiateMessage(domain, "")
		if err != nil {
			return nil, err
		}

		if resauth.IsNTLM() {
			req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(negotiateMessage))
		} else {
			req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(negotiateMessage))
		}

		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

		res, err = rt.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		// receive challenge?
		resauth = authheader(strings.Join(res.Header["Www-Authenticate"], " "))
		challengeMessage, err := resauth.GetData()
		if err != nil {
			return nil, err
		}
		if !(resauth.IsNegotiate() || resauth.IsNTLM()) || len(challengeMessage) == 0 {
			// Negotiation failed, let client deal with response
			return res, nil
		}
		io.Copy(ioutil.Discard, res.Body)
		res.Body.Close()

		// send authenticate
		authenticateMessage, err := ntlmssp.ProcessChallenge(challengeMessage, u, p)
		if err != nil {
			return nil, err
		}
		if resauth.IsNTLM() {
			req.Header.Set("Authorization", "NTLM "+base64.StdEncoding.EncodeToString(authenticateMessage))
		} else {
			req.Header.Set("Authorization", "Negotiate "+base64.StdEncoding.EncodeToString(authenticateMessage))
		}

		req.Body = ioutil.NopCloser(bytes.NewReader(body.Bytes()))

		res, err = rt.RoundTrip(req)
	}

	return res, err
}

type authheader string

func (h authheader) IsBasic() bool {
	return strings.Contains(string(h), "Basic ")
}

func (h authheader) IsNegotiate() bool {
	return strings.Contains(string(h), "Negotiate")
}

func (h authheader) IsNTLM() bool {
	return strings.Contains(string(h), "NTLM")
}

func (h authheader) GetData() ([]byte, error) {
	p := strings.Split(string(h), " ")
	if len(p) < 2 {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(string(p[1]))
}

func (h authheader) GetBasicCreds() (username, password string, err error) {
	d, err := h.GetData()
	if err != nil {
		return "", "", err
	}
	parts := strings.SplitN(string(d), ":", 2)
	return parts[0], parts[1], nil
}


var (
	siteURL  = flag.String("siteUrl", "", "SharePoint site URL")
	username = flag.String("username", "", "SharePoint user name, must be in the following format `domain\\username`")
	password = flag.String("password", "", "SharePoint password")
)

func main() {
	flag.Parse()

	auth := &strategy.AuthCnfg{
		SiteURL:  *siteURL,
		Username: *username,
		Password: *password,
	}
	client := &gosip.SPClient{
		AuthCnfg: auth,
	}

	// Workaround >>>
	if !strings.Contains(*username, "\\") {
		log.Fatal("incorrect username format, must be in the following format `domain\\username`")
	}
	client.Transport = &httpntlm.NtlmTransport{
	        Domain:   strings.Split(*username, "\\")[0],
		User:     strings.Split(*username, "\\")[1],
		Password: *password,
	}

        log.Printf("URL: %s", *siteURL)
        log.Printf("Auth:  %s / %s",  *username, *password)

        req, _ := http.NewRequest("GET", *siteURL, nil)
        res, _ := client.Do(req)

	log.Printf("%#v",res)
        log.Printf("\nStatus: %d\n", res.StatusCode)
}
