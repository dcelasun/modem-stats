package utils

import (
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Jeffail/gabs/v2"
)

func SimpleHTTPFetch(url string) ([]byte, int64, error) {
	timeStart := time.Now().UnixNano() / int64(time.Millisecond)
	resp, err := http.Get(url)
	if err != nil {
		return nil, 0, err
	}
	if resp.StatusCode != 200 {
		return nil, 0, fmt.Errorf("%d status code recieved", resp.StatusCode)
	}

	stats, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, err
	}
	fetchTime := (time.Now().UnixNano() / int64(time.Millisecond)) - timeStart
	return stats, fetchTime, nil
}

func RandomInt(min int, max int) int {
	rand.Seed(time.Now().UnixNano())
	random := rand.Intn(max-min) + min
	return random
}

func StringToMD5(input string) string {
	return fmt.Sprintf("%x", md5.Sum([]byte(input)))
}

func GabsInt(input *gabs.Container, path string) int {
	output, _ := strconv.Atoi(input.Path(path).String())
	return output
}

func GabsFloat(input *gabs.Container, path string) float64 {
	output, _ := strconv.ParseFloat(input.Path(path).String(), 64)
	return output
}

func GabsString(input *gabs.Container, path string) string {
	output := input.Path(path).String()
	return strings.Trim(output, "\"")
}

func Getenv(key, fallback string) string {
	value := os.Getenv(key)
	if len(value) == 0 {
		return fallback
	}
	return value
}

func FetchStats(router DocsisModem) (ModemStats, error) {
	stats, err := router.ParseStats()
	return stats, err
}

func ResetStats(router DocsisModem) {
	router.ClearStats()
}

type HttpResult struct {
	Index int
	Res   http.Response
	Err   error
}

func BoundedParallelGet(urls []string, concurrencyLimit int, httpClient *http.Client) []HttpResult {
	semaphoreChan := make(chan struct{}, concurrencyLimit)
	resultsChan := make(chan *HttpResult)

	defer func() {
		close(semaphoreChan)
		close(resultsChan)
	}()

	client := http.DefaultClient
	if httpClient != nil {
		client = httpClient
	}

	for i, url := range urls {
		go func(i int, url string) {
			semaphoreChan <- struct{}{}
			res, err := client.Get(url)
			if err != nil {
				panic(err)
			}
			result := &HttpResult{i, *res, err}
			resultsChan <- result
			<-semaphoreChan
		}(i, url)
	}

	var results []HttpResult
	for {
		result := <-resultsChan
		results = append(results, *result)
		if len(results) == len(urls) {
			break
		}
	}

	return results
}

func ExtractIntValue(valueWithUnit string) int {
	parts := strings.Split(valueWithUnit, " ")
	if len(parts) > 0 {
		intValue, err := strconv.Atoi(parts[0])
		if err == nil {
			return intValue
		}
	}
	return 0
}

func ExtractFloatValue(valueWithUnit string) float64 {
	parts := strings.Split(valueWithUnit, " ")
	if len(parts) > 0 {
		floatValue, err := strconv.ParseFloat(parts[0], 64)
		if err == nil {
			return floatValue
		}
	}
	return 0.0
}

func IsPortReachable(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), 5*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func GetHTTPClientWithCertificates(trustedCertificatesPEM ...[]byte) (*http.Client, error) {
	rootCAs, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("failed to get system cert pool: %v", err)
	}
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	for _, certPEM := range trustedCertificatesPEM {
		if !rootCAs.AppendCertsFromPEM(certPEM) {
			return nil, fmt.Errorf("failed to append custom certificate")
		}
	}

	tlsConfig := &tls.Config{
		RootCAs:            rootCAs,
		InsecureSkipVerify: true, // Required when using VerifyPeerCertificate
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("no certificates provided")
			}

			cert, err := x509.ParseCertificate(rawCerts[0])
			if err != nil {
				return fmt.Errorf("failed to parse certificate: %v", err)
			}

			opts := x509.VerifyOptions{
				Roots: rootCAs,
			}

			_, err = cert.Verify(opts)
			if err != nil {
				return fmt.Errorf("certificate verification failed: %v", err)
			}

			return nil
		},
	}

	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}, nil
}
