package main

import (
	"flag"
	"fmt"
	"log"
	"strings"
	"net/http"
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
        log.Printf("Auth:  %s / %s",  *username, *password)

        req, _ := http.NewRequest("GET", *siteURL, strings.NewReader(""))
        req.SetBasicAuth(*username, *password)
	res, _ := client.Do(req)
	fmt.Printf("\n--------------------\n3) Request\n%#V\n",req)

	log.Printf("%#v",res)
        log.Printf("\nStatus: %d\n", res.StatusCode)
}
