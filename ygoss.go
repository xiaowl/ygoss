// Pacage ygoss implements Yahoo BOSS API. https://developer.yahoo.com/boss/search/boss_api_guide/oauth_model.html
// uses OAuth v1.0, http://tools.ietf.org/html/rfc5849

package ygoss

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	CONSUMER_KEY     = "oauth_consumer_key"
	CONSUMER_SECRET  = "oauth_consumer_secret"
	OAUTH_VERSION    = "oauth_version"
	SIGNATURE_METHOD = "oauth_signature_method"
	OAUTH_TIMESTAMP  = "oauth_timestamp"
	OAUTH_NONCE      = "oauth_nonce"
	OAUTH_SIGNATURE  = "oauth_signature"
	OAUTH_HEADER     = "Authorization"
)

type OAuthSession struct {
	ConsumerKey    string
	ConsumerSecret string
}

type queryPair struct {
	Name  string
	Value string
}

type orderedQueryPair []queryPair

func (qs orderedQueryPair) Len() int      { return len(qs) }
func (qs orderedQueryPair) Swap(i, j int) { qs[i], qs[j] = qs[j], qs[i] }
func (qs orderedQueryPair) Less(i, j int) bool {
	if qs[i].Name < qs[j].Name {
		return true
	}
	if qs[i].Name > qs[j].Name {
		return false
	}
	return qs[i].Value < qs[j].Value
}

// build a base string for later signing  http://tools.ietf.org/html/rfc5849#section-3.4.1
func (session *OAuthSession) mkBaseString(request *http.Request) (string, map[string]string) {
	header := session.mkAuthorizationHeader()
	vals := request.URL.Query()
	for k, v := range header {
		vals[k] = []string{v}
	}
	return request.Method + "&" + escape(baseURI(request)) + "&" +
		escape(encodeParameters(vals)), header
}

// Authorize a http.Request instance, by adding OAuth header. http://tools.ietf.org/html/rfc5849#section-3.4
func (session *OAuthSession) Authorize(request *http.Request) {
	text, header := session.mkBaseString(request)
	// as we don't have a per-user token secret, so only "&" appended
	// http://tools.ietf.org/html/rfc5849#section-3.4.2
	key := escape(session.ConsumerSecret) + "&"
	mac := hmac.New(sha1.New, []byte(key))
	mac.Write([]byte(text))
	signature := mac.Sum(nil)
	header[OAUTH_SIGNATURE] = base64.StdEncoding.EncodeToString(signature)
	components := make([]string, 0)
	for n, v := range header {
		components = append(components, fmt.Sprintf(`%s="%s"`, n, v))
	}
	request.Header.Add(OAUTH_HEADER, "OAuth "+strings.Join(components, ","))
}

// Build the key-value pairs for authorization, used both in "sign" and "Authorization: " header
// NOTE: this method should only be called once, since each time this function run, it returns
// different oauth_nonce and oauth_timestampe.
func (session *OAuthSession) mkAuthorizationHeader() map[string]string {
	headers := make(map[string]string)
	headers[CONSUMER_KEY] = session.ConsumerKey
	headers[CONSUMER_SECRET] = session.ConsumerSecret
	headers[OAUTH_VERSION] = "1.0"
	buf := make([]byte, 8)
	rand.Read(buf)
	headers[OAUTH_NONCE] = hex.EncodeToString(buf)
	headers[SIGNATURE_METHOD] = "HMAC-SHA1"
	headers[OAUTH_TIMESTAMP] = fmt.Sprintf("%d", time.Now().Unix())

	return headers
}

func baseURI(request *http.Request) string {
	return request.URL.Scheme + "://" + request.URL.Host + request.URL.Path
}

// Normalize parameters http://tools.ietf.org/html/rfc5849#section-3.4.1.3.2
func encodeParameters(query map[string][]string) string {
	var encoded = make([]queryPair, 0)
	for name, value := range query {
		n := escape(name)
		for _, v := range value {
			encoded = append(encoded, queryPair{n, escape(v)})
		}
	}
	sort.Sort(orderedQueryPair(encoded))
	escaped := make([]string, 0)
	for _, pair := range encoded {
		escaped = append(escaped, pair.Name+"="+pair.Value)
	}
	return strings.Join(escaped, "&")
}

// helpers from https://github.com/mrjones/oauth/blob/master/oauth.go#L591
func escape(s string) string {
	t := make([]byte, 0, 3*len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isEscapable(c) {
			t = append(t, '%')
			t = append(t, "0123456789ABCDEF"[c>>4])
			t = append(t, "0123456789ABCDEF"[c&15])
		} else {
			t = append(t, s[i])
		}
	}
	return string(t)
}

func isEscapable(b byte) bool {
	return !('A' <= b && b <= 'Z' || 'a' <= b && b <= 'z' || '0' <= b && b <= '9' || b == '-' || b == '.' || b == '_' || b == '~')
}

// end of helpers
