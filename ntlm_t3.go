package main

import (
	"fmt"
	"log"
	"flag"
	"strings"

	"github.com/koltyakov/gosip"
	"github.com/koltyakov/gosip/api"
	strategy "github.com/koltyakov/gosip/auth/ntlm"
)
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

	spClient := api.NewHTTPClient(&gosip.SPClient{AuthCnfg: auth})

	endpoint := auth.GetSiteURL()
		if !strings.Contains(*username, "\\") {
		log.Fatal("incorrect username format, must be in the following format `domain\\username`")
	}
//	spClient.Transport = &httpntlm.NtlmTransport{
//	        Domain:   strings.Split(*username, "\\")[0],
//		User:     strings.Split(*username, "\\")[1],
//		Password: *password,
//	}

	data, err := spClient.Get(endpoint, nil)
	if err != nil {
			log.Fatalf("%v\n", err)
	}

	// spClient.Post(endpoint, body, nil) // generic POST

	// generic DELETE helper crafts "X-Http-Method"="DELETE" header
	// spClient.Delete(endpoint, nil)

	// generic UPDATE helper crafts "X-Http-Method"="MERGE" header
	// spClient.Update(endpoint, body, nil)

	// CSOM helper (client.svc/ProcessQuery)
	// spClient.ProcessQuery(endpoint, body, nil)

	fmt.Printf("response: %s\n", data)
}
