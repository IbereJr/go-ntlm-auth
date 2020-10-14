package main

import (
    "os"
    "fmt"
    "log"
    "strings"
    "net/http"
    "github.com/Azure/go-ntlmssp"
)

func main() {
    siteURL:= os.Args[1]
    username:= os.Args[2]
    password:= os.Args[3]

    client := &http.Client{ Transport: ntlmssp.Negotiator{ RoundTripper:&http.Transport{}, }, }


        log.Printf("URL: %s", siteURL)
        log.Printf("Auth:  %s / %s",  username, password)

        req, _ := http.NewRequest("GET", siteURL, strings.NewReader(""))
        req.SetBasicAuth(username, password)
    res, _ := client.Do(req)
    fmt.Printf("\n--------------------\n3) Request\n%#V\n",req)

    log.Printf("%#v",res)
        log.Printf("\nStatus: %d\n", res.StatusCode)
}
 