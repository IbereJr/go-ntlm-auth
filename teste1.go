package main

import (
    "io"
    "os"
    "bytes"
    "fmt"
    "net/url"
    "net/http"
    "io/ioutil"
    "log"
    "github.com/Azure/go-ntlmssp"
)

func main(){

    executeMain(os.Args[1], os.Args[2], os.Args[3])

}

func getData() url.Values{
    data := url.Values{}
    data.Set("key1", "100")
    data.Set("key2", "1")
    return data
}

func getReq(_url string, _user string, _password string, b io.Reader) *http.Request {
    req, err := http.NewRequest("POST", _url,  b)
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Accept", "application/json")
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
    b := bytes.NewBufferString(getData().Encode())

    req := getReq(url_, user_, password_, b)

    fmt.Println("Efetuando Request:")
    resp, err := client.Do(req)
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

