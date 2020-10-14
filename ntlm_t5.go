package main

import (
//    "io/ioutil"
    "log"
    "flag"
    "net/http"
    //"crypto/tls"
    "strings"

    "github.com/vadimi/go-http-ntlm"
)

var (
	siteURL  = flag.String("siteUrl", "", "SharePoint site URL")
	domain   = flag.String("domain", "", "Domain")
	username = flag.String("username", "", "SharePoint user name, must be in the following format `domain\\username`")
	password = flag.String("password", "", "SharePoint password")
)

func main() {
    flag.Parse()
    url := *siteURL
    dom := *domain
    usr := *username
    pwd := *password
    // configure http client
    client := http.Client{
        Transport: &httpntlm.NtlmTransport{
            Domain:   dom,
            User:     usr,
            Password: pwd,
            RoundTripper: &http.Transport{
                // provide tls config
	    //            TLSClientConfig: &tls.Config{InsecureSkipVerify : true},
                // other properties RoundTripper, see http.DefaultTransport
            },
        },
    }

    log.Printf("URL: %s", url)
    log.Printf("Auth: %s -  %s / %s", dom,  usr, pwd)

    req, err := http.NewRequest("GET", url, strings.NewReader(""))
    resp, err := client.Do(req)

    if err != nil {
        log.Fatal(err)
    }

    defer func() {
        err := resp.Body.Close()
        if err != nil {
            log.Fatal(err)
        }
    }()

    //body, err := ioutil.ReadAll(resp.Body)
    //if err != nil {
    //    log.Fatal(err)
    //}

    //log.Printf("%#v",body)
    log.Printf("Status: %d\n", resp.StatusCode)
}
