package main

import (
	"flag"
	"fmt"
	"github.com/xiaowl/ygoss"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
)

var (
	key     = flag.String("key", "", "Consumer key for Yahoo BOSS API. Required.")
	secret  = flag.String("secret", "", "Consumer secret for Yahoo BOSS API. Required.")
	keyword = flag.String("search", "yahoo boss search api", "Keywords to search.")
)

func main() {
	flag.Parse()
	if *key == "" || *secret == "" {
		flag.Usage()
		os.Exit(1)
	}
	session := ygoss.OAuthSession{*key, *secret}
	u := fmt.Sprintf("https://yboss.yahooapis.com/ysearch/web?q=%s&format=json&count=50&market=en-us&abstract=long&style=raw", ygoss.Escape(*keyword))
	println(u)
	uu, err := url.Parse(u)
	if err != nil {
		panic(err)
	}
	session.AuthorizeURL(uu)
	println(uu.String())
	req, err := http.NewRequest("GET", uu.String(), nil)
	if err != nil {
		panic(err)
	}
	// session.AuthorizeRequest(req)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	content, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(content))
}
