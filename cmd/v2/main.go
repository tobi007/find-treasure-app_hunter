package main

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"math/rand"

	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mergermarket/go-pkcs7"
)

var mu sync.Mutex

type TokenResponse struct {
	Token string `json:"token"`
}

type Hunter struct {
	visited       map[string]string
	unvisitedNode chan string
	cache         map[string]string
	decryptedPath map[string]string
	accessToken   string
}

type Encryption struct {
	Algorithm string `json:algorithm`
	Key       string `json:key`
}

type Path struct {
	CipherId string `json:cipherId`
	N        int    `json:n`
}

type CovenPath struct {
	Encryption Encryption `json:encryption`
	Paths      []Path     `json:paths`
}

func decryptPath(algorithm, encKey, encrypted string, numEncrypted int) string {

	key := []byte(encKey)
	cipherText, _ := hex.DecodeString(encrypted)

	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	if len(cipherText) < aes.BlockSize {
		panic("cipherText too short")
	}
	iv := encKey[:aes.BlockSize]

	if len(cipherText)%aes.BlockSize != 0 {
		panic("cipherText is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(cipherText, cipherText)

	cipherText, _ = pkcs7.Unpad(cipherText, aes.BlockSize)

	if numEncrypted > 1 {
		newNum := numEncrypted - 1
		return decryptPath(algorithm, encKey, fmt.Sprintf("%s", cipherText), newNum)
	} else {
		return fmt.Sprintf("%s", cipherText)
	}
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

func (hunter *Hunter) writeCache(url, response string) {
	mu.Lock()
	defer mu.Unlock()
	hunter.cache[url] = response
	go writeToFile(url+">>>"+response, "visited.txt")
}

func (hunter *Hunter) isCached(url string) (string, bool) {
	mu.Lock()
	defer mu.Unlock()
	visited, exists := hunter.cache[url]
	return visited, exists
}

func writeToFile(data, fileName string) {

	file, err := os.OpenFile(fileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)

	if err != nil {
		log.Fatalf("failed creating file: %s", err)
	}

	datawriter := bufio.NewWriter(file)

	_, _ = datawriter.WriteString(data + "\n")

	datawriter.Flush()
	file.Close()
}

func (hunter *Hunter) writeDecryptedPath(encrypted, decrypted string) {
	mu.Lock()
	defer mu.Unlock()
	hunter.decryptedPath[encrypted] = decrypted
	go writeToFile(encrypted+">>>"+decrypted, "decryptedPath.txt")
}

func (hunter *Hunter) writeVisited(url string) {
	mu.Lock()
	defer mu.Unlock()
	hunter.visited[url] = "response"
}

func (hunter *Hunter) isVisited(url string) bool {
	mu.Lock()
	defer mu.Unlock()
	_, exists := hunter.visited[url]
	return exists
}

func (hunter *Hunter) writeUnVisited(url string) {
	mu.Lock()
	defer mu.Unlock()
	hunter.unvisitedNode <- url
}

func (hunter *Hunter) getUnVisited() string {

	r, _ := <-hunter.unvisitedNode
	return r

}

func (hunter *Hunter) hunt(nodeURL string) {

	visited, exists := hunter.isCached(nodeURL)
	var buf bytes.Buffer

	if exists {
		fmt.Println("Using Cache")
		buf.WriteString(visited)
	} else {
		r, err := http.NewRequest(
			http.MethodGet,
			"https://findtreasure.app/api/v1/games/cipher/"+nodeURL,
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
			fmt.Println(err)
			hunter.writeUnVisited(nodeURL)
			time.Sleep(time.Second * time.Duration(300))
			go hunter.hunt(nodeURL)
			return
		}

		defer res.Body.Close()
		if res.StatusCode <= http.StatusFound {

			if res.StatusCode == http.StatusFound {
				fmt.Println("Found: " + nodeURL)
			} else if res.StatusCode == http.StatusAlreadyReported {
				fmt.Println("Not Yours: " + nodeURL)
			}

			if _, err := io.Copy(&buf, res.Body); err != nil {
				fmt.Println("Error Copying Response")
				fmt.Println(err)
			}

			hunter.writeCache(nodeURL, buf.String())
		} else {
			if res.StatusCode == http.StatusTooManyRequests {
				fmt.Println("Too Many Requests")
				hunter.writeUnVisited(nodeURL)

				time.Sleep(time.Second * time.Duration(300))
				//go hunter.hunt(nodeURL)
				return

			}
			if res.StatusCode == http.StatusUnauthorized {
				fmt.Println("Refreshing Token")
				os.Exit(1)
			}
			if res.StatusCode == http.StatusNotFound {
				fmt.Println("Path Not found")
				//os.Exit(1)
			}
			if res.StatusCode == http.StatusInternalServerError {
				fmt.Println("Server Error")
				hunter.writeUnVisited(nodeURL)

				time.Sleep(time.Second * time.Duration(300))
				//go hunter.hunt(nodeURL)
				return
			}
		}
	}

	hunter.writeVisited(nodeURL)
	coven := new(CovenPath)
	json.Unmarshal(buf.Bytes(), coven)

	for i := 0; i < len(coven.Paths); i++ {
		numEncrypted := coven.Paths[i].N
		cipherText := coven.Paths[i].CipherId
		key := coven.Encryption.Key
		algorithm := coven.Encryption.Algorithm

		path, exists := hunter.decryptedPath[cipherText]
		if !exists {
			path = decryptPath(algorithm, key, cipherText, numEncrypted)
			hunter.writeDecryptedPath(cipherText, path)
		}

		if !hunter.isVisited(path) {
			go hunter.writeUnVisited(path)
			sz := len(hunter.unvisitedNode)
			//fmt.Println(path + ": Active Connection " + strconv.Itoa(sz))

			time.Sleep(time.Second * time.Duration(sz*5))

			//hunter.hunt(nodeURL)
		}
	}
}

func main() {

	accessToken := refreshToken()

	startURL := "start"

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

	file, err = os.Open("decryptedPath.txt")
	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	scanner = bufio.NewScanner(file)
	decrypted := make(map[string]string)

	for scanner.Scan() {
		rest := strings.Split(scanner.Text(), ">>>")
		decrypted[rest[0]] = rest[1]
	}

	log.Println("Already Visited: " + strconv.Itoa(len(visited)))
	log.Println("Already decrypted: " + strconv.Itoa(len(decrypted)))

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	h := Hunter{
		accessToken:   accessToken,
		cache:         visited,
		visited:       make(map[string]string),
		unvisitedNode: make(chan string, 6000),
		decryptedPath: decrypted,
	}

	go h.hunt(startURL)

	nodeVisited := 1

	notCached := make(chan string, 6000)
	delay := time.Second * 6
	timer := time.NewTimer(delay)
	for {
		select {

		case nodeURL := <-h.unvisitedNode:
			_, exists := h.cache[nodeURL]
			if exists {
				//time.Sleep(time.Second * time.Duration(1))
				go h.hunt(nodeURL)
				nodeVisited++
				fmt.Println("Node Visited chann: " + strconv.Itoa(nodeVisited))
			} else {
				notCached <- nodeURL
			}

		case <-timer.C:
			////////////Nah THe Sauce be this///////////////////
			notCatchedLength := len(notCached)
			if notCatchedLength > 0 {
				for i := 0; i < rand.Intn(notCatchedLength); i++ {
					nodeURL := <-notCached
					_, exists := h.cache[nodeURL]
					if !exists {
						notCached <- nodeURL
					}
				}
			}
			////////////////////////////////////////////////////
			for i := 0; i < len(notCached); i++ {
				nodeURL := <-notCached
				_, exists := h.cache[nodeURL]
				if !exists {
					go h.hunt(nodeURL)
					timer.Reset(delay)
					nodeVisited++
					break
				}
			}
			fmt.Println("notCached: " + strconv.Itoa(len(notCached)))
			fmt.Println("Node Visited timer: " + strconv.Itoa(nodeVisited))
		}
	}

	running := make(chan bool)
	<-running
}
