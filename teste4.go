package main

 

import (
    "os"
    "fmt"
    "log"
    "strings"
    "net/http"

    "github.com/koltyakov/gosip"
    strategy "github.com/koltyakov/gosip/auth/ntlm"
    httpntlm "github.com/vadimi/go-http-ntlm"
)


func main() {
    siteURL:= os.Args[1]
    username:= os.Args[2]
    password:= os.Args[3]

    auth := &strategy.AuthCnfg{
        SiteURL:  siteURL,
        Username: username,
        Password: password,
    }
    client := &gosip.SPClient{
        AuthCnfg: auth,
    }

    // Workaround >>>
    if !strings.Contains(username, "\\") {
        log.Fatal("incorrect username format, must be in the following format `domain\\username`")
    }
    client.Transport = &httpntlm.NtlmTransport{
            Domain:   strings.Split(username, "\\")[0],
        User:     strings.Split(username, "\\")[1],
        Password: password,
    }

        log.Printf("URL: %s", siteURL)
        log.Printf("Auth:  %s / %s",  username, password)

        req, _ := http.NewRequest("GET", siteURL, strings.NewReader(""))
        req.SetBasicAuth(username, password)
    res, _ := client.Do(req)
    fmt.Printf("\n--------------------\n3) Request\n%#V\n",req)

    log.Printf("%#v",res)
        log.Printf("\nStatus: %d\n", res.StatusCode)
}