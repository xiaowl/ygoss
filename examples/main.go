package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"ygoss"
)

var (
	key     = flag.String("key", "", "Consumer key for Yahoo BOSS API. Required.")
	secret  = flag.String("secret", "", "Consumer secret for Yahoo BOSS API. Required.")
	keyword = flag.String("search", "yahoo", "Keywords to search.")
)

func main() {
	flag.Parse()
	if *key == "" || *secret == "" {
		flag.Usage()
		os.Exit(1)
	}
	url := fmt.Sprintf("https://yboss.yahooapis.com/ysearch/news,web?q=%s&format=json", *keyword)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		panic(err)
	}
	session := ygoss.OAuthSession{*key, *secret}
	session.Authorize(req)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	content, _ := ioutil.ReadAll(resp.Body)
	fmt.Println(string(content))
}
