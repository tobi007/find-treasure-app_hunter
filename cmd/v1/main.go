package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	// "strings"
	"sync"
)

var mu sync.Mutex

type TokenResponse struct {
	Token string `json:"token"`
}

type Treasure struct {
	Total int `json:total`
	Found int `json:found`
}

type CovenPath struct {
	Paths     []string `json:paths`
	Treasures Treasure `json:treasures`
}

func registerEmail() string {
	fmt.Println("Here")

	var registrationRequest bytes.Buffer
	registrationRequestObj := struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	}{
		Name:  "Your Name Goes Here",
		Email: "your_email@domain",
	}

	if err := json.NewEncoder(&registrationRequest).Encode(registrationRequestObj); err != nil {
		fmt.Println("Error Enciding")
		fmt.Println(err)
		return ""
	}

	r, err := http.NewRequest(
		http.MethodPost,
		"https://findtreasure.app/api/v1/contestants/register",
		&registrationRequest,
	)
	if err != nil {
		fmt.Println("Error Connecting")
		fmt.Println(err)
		return ""
	}

	r.Header.Set("Content-Type", "application/json; charset=utf-8")

	res, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		fmt.Println("Error Making Request")
		fmt.Println(err)
		return ""
	}

	defer res.Body.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, res.Body); err != nil {
		fmt.Println("Error Copying Response")
		fmt.Println(err)
		return ""
	}

	return buf.String()
}

func refreshToken() string {

	var tokenRequest bytes.Buffer
	tokenRequestObj := struct {
		Email string `json:"email"`
	}{
		Email: "your_email@domain",
	}

	if err := json.NewEncoder(&tokenRequest).Encode(tokenRequestObj); err != nil {
		fmt.Println("Error Enciding")
		fmt.Println(err)
		return ""
	}

	r, err := http.NewRequest(
		http.MethodPost,
		"https://findtreasure.app/api/v1/contestants/refresh",
		&tokenRequest,
	)

	if err != nil {
		fmt.Println("Error Connecting")
		fmt.Println(err)
		return ""
	}
	r.Header.Set("Content-Type", "application/json; charset=utf-8")

	res, err := http.DefaultTransport.RoundTrip(r)
	if err != nil {
		fmt.Println("Error Making Request")
		fmt.Println(err)
		return ""
	}

	defer res.Body.Close()
	resp := new(TokenResponse)
	if res.StatusCode == http.StatusOK {
		defer res.Body.Close()
		var buf bytes.Buffer
		if _, err := io.Copy(&buf, res.Body); err != nil {
			return ""
		}
		json.Unmarshal(buf.Bytes(), resp)
	}

	fmt.Println(resp.Token)
	return resp.Token
}

type Hunter struct {
	startTime     int
	visited       map[string]string
	unvisitedNode map[string]string
	cache         map[string]string
	accessToken   string
}

func (hunter *Hunter) writeUnVisited(url string) {
	mu.Lock()
	defer mu.Unlock()
	hunter.unvisitedNode[url] = "response"

}

func (hunter *Hunter) deleteUnVisited(url string) {
	mu.Lock()
	defer mu.Unlock()
	delete(hunter.unvisitedNode, url)
}

func (hunter *Hunter) writeVisited(url, response string) {
	mu.Lock()
	defer mu.Unlock()
	hunter.visited[url] = response

}

func (hunter *Hunter) writeCache(url, response string) {
	mu.Lock()
	defer mu.Unlock()
	hunter.cache[url] = response
	writeVisitedToFile(url+">>>"+response, "visited.txt")
}

func writeVisitedToFile(data, fileName string) {

	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	datawriter := bufio.NewWriter(file)

	_, _ = datawriter.WriteString(data + "\n")

	datawriter.Flush()
	file.Close()
}

func (hunter *Hunter) isVisited(url string) bool {
	mu.Lock()
	defer mu.Unlock()
	_, exist := hunter.visited[url]
	return exist
}

func (hunter *Hunter) incrementTimer() {
	mu.Lock()
	defer mu.Unlock()
	hunter.startTime++
}

func (hunter Hunter) getTimer() int {
	return hunter.startTime
}

func (hunter *Hunter) getAccessToken() {
	mu.Lock()
	defer mu.Unlock()
	hunter.accessToken = refreshToken()
}

func (hunter *Hunter) hunt(nodeURL string, counter int) {

	visited, exists := hunter.cache[nodeURL]
	var buf bytes.Buffer

	if exists {
		log.Println("Using Cache")
		buf.WriteString(visited)
	} else {
		r, err := http.NewRequest(
			http.MethodGet,
			nodeURL,
			nil,
		)
		if err != nil {
			fmt.Println("Error Creating Request")
			fmt.Println(err)
		}

		r.Header.Set("gomoney", "***********")
		r.Header.Set("Authorization", "Bearer "+hunter.accessToken)

		res, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			fmt.Println("Error Making Request To Node")
			fmt.Println(err)
			go hunter.hunt(nodeURL, counter)
			return
		}

		defer res.Body.Close()

		if res.StatusCode <= http.StatusFound {
			fmt.Println("Positive Response: " + res.Status)

			if _, err := io.Copy(&buf, res.Body); err != nil {
				fmt.Println("Error Copying Response")
				fmt.Println(err)
			}

			hunter.writeCache(nodeURL, buf.String())
			log.Println("Counter: " + strconv.Itoa(counter) + " Done with Reqwuest: " + nodeURL)
		} else {
			if res.StatusCode == http.StatusTooManyRequests {
				time.Sleep(time.Second * time.Duration(60))
				go hunter.hunt(nodeURL, counter)
			}
			if res.StatusCode == http.StatusUnauthorized {
				log.Println("Refreshing Token")
				os.Exit(1)
			}
			if res.StatusCode == http.StatusInternalServerError {
				log.Println(strconv.Itoa(counter) + "  " + res.Status)
				go hunter.hunt(nodeURL, counter)
			}

		}
	}

	coven := new(CovenPath)
	json.Unmarshal(buf.Bytes(), coven)

	for i := 0; i < len(coven.Paths); i++ {
		path := coven.Paths[i]
		if !hunter.isVisited(path) {
			fmt.Println("Counter " + strconv.Itoa(hunter.getTimer()))
			time.Sleep(time.Second * time.Duration((i+1)*10))
			go hunter.hunt(coven.Paths[i], hunter.getTimer())
			hunter.incrementTimer()
			hunter.writeUnVisited(path)
		}
	}

	hunter.writeVisited(nodeURL, buf.String())
	hunter.deleteUnVisited(nodeURL)

	log.Println("Pending Request Node: " + strconv.Itoa(len(hunter.unvisitedNode)))
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	//fmt.Println(registerEmail())
	accessToken := refreshToken()
	startURL := "https://findtreasure.app/api/v1/games/ileya/start"

	file, err := os.Open("visited.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	visited := make(map[string]string)

	for scanner.Scan() {
		rest := strings.Split(scanner.Text(), ">>>")
		visited[rest[0]] = rest[1]
	}

	log.Println("Already Visited: " + strconv.Itoa(len(visited)))

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	h := Hunter{
		accessToken:   accessToken,
		startTime:     0,
		cache:         visited,
		visited:       make(map[string]string),
		unvisitedNode: make(map[string]string),
	}
	h.hunt(startURL, 0)

	running := make(chan bool)
	<-running
}
