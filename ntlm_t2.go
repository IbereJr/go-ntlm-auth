package main

import (
//    "io/ioutil"
    "os"
    "log"
    "net/http"
    "crypto/tls"
    "strings"

    "github.com/vadimi/go-http-ntlm"
)

func main() {
    url := os.Args[1]
  //  dom := os.Args[2]
    usr := os.Args[2]
    pwd := os.Args[3]
    // configure http client
    client := http.Client{
        Transport: &httpntlm.NtlmTransport{
     //       Domain:   "mydomain",  EMS-WINNT or MULTILAB
     //       Domain:   dom,
            User:     usr,
            Password: pwd,
            // Configure RoundTripper if necessary, otherwise DefaultTransport is used
            RoundTripper: &http.Transport{
                // provide tls config
                TLSClientConfig: &tls.Config{InsecureSkipVerify : true},
                // other properties RoundTripper, see http.DefaultTransport
            },
        },
    }

    log.Printf("URL: %s", url)
    log.Printf("Auth:  %s / %s",  usr, pwd)

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

    log.Println("Passou OK")
    //log.Printf("%#v",body)
    log.Printf("Status: %d\n", resp.StatusCode)
}
