package main

import (
	"encoding/json"
	"fmt"
	"github.com/gocolly/colly/v2"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	mainURL  = "https://wichart.vn"
	loginURL = "https://wichart.vn/wichartapi/wichart/taikhoan/dangnhap"
	email    = ""
	password = ""
)

var (
	loginInfo = map[string]string{"email": email, "password": password}
)

func addTimeSuffix(fileName string, now int64) string {
	return fmt.Sprintf("%s-%d", fileName, now)
}

type wiChartAuthenticator struct {
	token   string
	cookies []*http.Cookie
}

func (r *wiChartAuthenticator) GetBearerToken(c *colly.Collector) {

	c.OnRequest(func(r *colly.Request) {
		if len(fmt.Sprintf("%s", r.URL)) != 0 {
			log.Println("requesting to login", r.URL)
		}
	})

	c.OnResponse(func(req *colly.Response) {
		log.Println("login response status", req.StatusCode)
		if req.StatusCode == http.StatusOK {
			log.Println("login data", string(req.Body))

			if token := getToken(req.Body); len(token) != 0 {
				r.token = token
				r.cookies = c.Cookies(loginURL)
				log.Println("token and cookies was added", token)
			} else {
				log.Panicln("can not get token")
			}
		} else {
			log.Panicln("Failed to req login")
		}
	})

	cookies := c.Cookies(mainURL)
	if err := c.SetCookies(loginURL, cookies); err != nil {

	}
	if err := c.Post(loginURL, loginInfo); err != nil {
		log.Panicln("can not make the login req", err)
	}
}

func (r *wiChartAuthenticator) GetAuthenticatedProxy(req *http.Request) (*url.URL, error) {
	authenticationToken := fmt.Sprintf("Bearer %s", r.token)
	req.Header.Add("Authorization", authenticationToken)
	for _, c := range r.cookies {
		req.AddCookie(c)
	}
	return req.URL, nil
}

func main() {

	now := time.Now().Unix()

	//client := &http.Client{}
	//loginBody, err := json.Marshal(loginInfo)
	//req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewBuffer(loginBody))
	//if err != nil {
	//	log.Panicln("Failed to create req", err)
	//}

	//resp, err := client.Do(req)
	//if err != nil {
	//	log.Panicln("Failed to request", err)
	//}
	//
	//defer func(resp *http.Response) { _ = resp.Body.Close() }(resp)
	//respBody, err := ioutil.ReadAll(resp.Body)
	//if err != nil {
	//	log.Fatal(err)
	//}
	//
	//if contentType := resp.Header.Get("Content-Type"); len(contentType) != 0 && contentType == "text/html" {
	//	f, err := os.Create("./data/login-file.html")
	//	if err != nil {
	//		log.Panic("can not create file", err)
	//	}
	//
	//	defer func() { _ = f.Close() }()
	//	if _, err := f.Write([]byte(fmt.Sprintf("%s\n", respBody))); err != nil {
	//		log.Println("ERROR: failed to write login resp file", err)
	//	}
	//} else {
	//	log.Println("resp data", string(respBody))
	//}
	//

	f, err := os.Create(addTimeSuffix("./data/data", now))
	if err != nil {
		log.Panic("can not create file", err)
	}
	defer func() { _ = f.Close() }()

	c := colly.NewCollector(
		colly.AllowedDomains("wichart.vn", "www.wichart.vn", "wigroup.vn", "www.wigroup.vn"),
	)

	wiAuth := wiChartAuthenticator{}
	wiAuth.GetBearerToken(c)

	crawlCollector := c.Clone()
	crawlCollector.WithTransport(&http.Transport{
		Proxy: wiAuth.GetAuthenticatedProxy,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSNextProto:          nil,
	})

	words := []string{}
	//crawlCollector.OnHTML("li", func(e *colly.HTMLElement) {
	//	words = append(words, e.Text)
	//})

	crawlCollector.OnHTML("a[href]", func(e *colly.HTMLElement) {
		_ = e.Request.Visit(e.Attr("href"))
	})

	crawlCollector.OnRequest(func(r *colly.Request) {
		if len(fmt.Sprintf("%s", r.URL)) != 0 {
			log.Println("visiting", r.URL)
		}
	})

	crawlCollector.OnResponse(func(resp *colly.Response) {

		if err := resp.Save(fmt.Sprintf("./data/%s", resp.Request.URL)); err != nil {
			log.Println("ignore response for", resp.Request.URL)
		}
	})

	if err := crawlCollector.Visit("https://wichart.vn/dashboard"); err != nil {
		log.Panic("crawl failed", err)
	}
	for _, p := range words {
		fmt.Printf("%s\n", p)
	}
}

func getToken(b []byte) string {
	data := struct {
		Token     string `json:"token,omitempty	"`
		Trustable bool   `json:"isTrust,omitempty"`
	}{}
	if err := json.Unmarshal(b, &data); err != nil {
		return ""
	}
	return data.Token
}
