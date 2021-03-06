package main

import (
//    "io/ioutil"
    "flag"
    "log"
    "net/http"
//    "crypto/tls"
//    "strings"

    "github.com/Azure/go-ntlmssp"
)

var (
        siteURL  = flag.String("siteUrl", "", "SharePoint site URL")
        username = flag.String("username", "", "SharePoint user name, must be in the following format `domain\\username`")
        password = flag.String("password", "", "SharePoint password")
)

func main() {

    flag.Parse()
    client := &http.Client{ Transport: ntlmssp.Negotiator{ RoundTripper:&http.Transport{}, }, }

    log.Printf("URL: %s", *siteURL)
    log.Printf("Auth: %s / %s", *username, *password)

    req, _ := http.NewRequest("GET", *siteURL, nil)
    req.SetBasicAuth(*username, *password)
    res, _ := client.Do(req)

    //if err != nil { log.Fatal(err) }

    //body, err := ioutil.ReadAll(resp.Body)
    //if err != nil {
    //    log.Fatal(err)
    //}

    //log.Printf("%#v",body)
    log.Printf("Status: %d\n", res.StatusCode)
}
