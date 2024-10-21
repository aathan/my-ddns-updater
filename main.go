package main

import (
	"bytes"
	//"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/huin/goupnp/dcps/internetgateway1"
)

const (
	ipCheckURL      = "http://192.168.98.1/RST_st_dhcp.htm"
	ipLoginURL      = "http://192.168.98.1"
	nameComAPIURL   = "https://api.name.com/v4"
	nameComUsername = "aathan"
	httpTimeout     = 10 * time.Second
)

type Record struct {
	ID     int    `json:"id"`
	Type   string `json:"type"`
	Host   string `json:"host"`
	Answer string `json:"answer"`
}

type ListRecordsResponse struct {
	Records []Record `json:"records"`
}

type Config struct {
	NameComToken      string `json:"nameComToken"`
	GetIPPassword     string `json:"getIPPassword"`
	GetIPUsername     string `json:"getIPUsername"`
	DisableUPnP       bool   `json:"disableUPnP"`
	Host              string `json:"host"`
	Domain            string `json:"domain"`
	CheckInterval     string `json:"checkInterval"`
	UpdateInterval    string `json:"updateInterval"`
	IgnoreDNSInterval string `json:"ignoreDNSInterval"`
}

var config Config
var fqdn string

func main() {
	configPath := flag.String("config", "config.json", "Path to the configuration file")
	disableUPnP := flag.Bool("disable-upnp", false, "Disable UPnP for getting public IP")
	checkInterval := flag.Duration("check-interval", 0, "Check interval")
	updateInterval := flag.Duration("update-interval", 0, "Update interval")
	ignoreDNSInterval := flag.Duration("ignore-dns-interval", 0, "Ignore DNS interval")
	flag.Parse()

	if err := loadConfig(*configPath); err != nil {
		log.Fatalf("Error loading configuration: %v", err)
	}

	// Override config settings if command-line flags are set
	if *disableUPnP {
		config.DisableUPnP = true
	}
	if *checkInterval != 0 {
		config.CheckInterval = checkInterval.String()
	}
	if *updateInterval != 0 {
		config.UpdateInterval = updateInterval.String()
	}
	if *ignoreDNSInterval != 0 {
		config.IgnoreDNSInterval = ignoreDNSInterval.String()
	}

	// Set fqdn after loading config
	fqdn = config.Host + "." + config.Domain

	checkIntervalDuration, _ := time.ParseDuration(config.CheckInterval)
	updateIntervalDuration, _ := time.ParseDuration(config.UpdateInterval)
	ignoreDNSIntervalDuration, _ := time.ParseDuration(config.IgnoreDNSInterval)

	now := time.Now()
	lastUpdateTime := now.Add(-updateIntervalDuration) // Initialize to allow immediate update if needed
	lastIgnoreDNSTime := lastUpdateTime

	jar, err := cookiejar.New(nil)
	if err != nil {
		log.Fatalf("Error creating cookie jar: %v", err)
		return
	}
	//log.Printf("has cookie: %v", hasXSRFToken(jar))

	client := &http.Client{
		Jar:     jar,
		Timeout: httpTimeout,
	}

	firstRun := true
	for {
		if !firstRun {
			time.Sleep(checkIntervalDuration)
		}
		firstRun = false

		currentIP, err := getCurrentIP(client, jar)
		if err != nil {
			if err.Error() == "exit" {
				log.Printf("exit")
				continue
			}

			log.Printf("Error detecting current IP: %v", err)
			continue
		}
		log.Printf("Detected current IP: %s\n", currentIP)

		var dnsIP string
		now := time.Now()

		dnsIP, err = queryDNS()
		if err != nil {
			log.Printf("Error getting FQDN IP: %v", err)
		}
		if time.Since(lastIgnoreDNSTime) >= ignoreDNSIntervalDuration {
			lastIgnoreDNSTime = now
		}

		if dnsIP == currentIP {
			if lastIgnoreDNSTime != now {
				log.Printf("Detected IP matches FQDN IP: %s", dnsIP)
				continue
			} else {
				log.Printf("Detected IP matches FQDN IP: %s, time to double check API record", dnsIP)
			}
		} else {
			log.Printf("Detected IP does not match FQDN IP: %s, fetching API record", dnsIP)
		}

		dnsRecord, err := fetchAPIRecord()
		if err != nil {
			log.Printf("Error getting API record: %v", err)
			continue
		}

		priorIP := dnsRecord.Answer
		if currentIP != priorIP {
			if time.Since(lastUpdateTime) >= updateIntervalDuration {
				err = updateAPIRecord(currentIP, dnsRecord.ID)
				if err != nil {
					log.Printf("Error updating API record: %v", err)
				} else {
					log.Printf("API record updated. Prior IP: %s, New IP: %s", priorIP, currentIP)
					lastUpdateTime = now
				}
			} else {
				log.Printf("IP change detected, but waiting for update interval. Current IP: %s, DNS IP: %s", currentIP, dnsRecord.Answer)
			}
		} else {
			log.Printf("IP unchanged: %s", currentIP)
		}
	}
}

func loadConfig(path string) error {
	file, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}

	err = json.Unmarshal(file, &config)
	if err != nil {
		return fmt.Errorf("error parsing config file: %v", err)
	}

	return nil
}

func getRequest(url string, client *http.Client, postData *url.Values) (string, int, error) {
	var req *http.Request
	var err error

	if postData != nil {
		encodedData := postData.Encode()
		req, err = http.NewRequest("POST", url, strings.NewReader(encodedData))
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		req, err = http.NewRequest("GET", url, nil)
	}

	if req != nil {
		log.Printf("Requesting URL: %s\n", req.URL.String())
	}

	if err != nil {
		log.Printf("Error creating request: %v", err)
		return "", 0, err
	}

	setAuth(req)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error making request: %v", err)
		return "", 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		log.Printf("200OK Response")
		return string(body), resp.StatusCode, nil
	}
	return "", resp.StatusCode, fmt.Errorf("status code: %d", resp.StatusCode)
}

func loginAndGetCookie(client *http.Client, jar *cookiejar.Jar) error {

	// Make a request to get the cookie
	for i := 0; i < 2; i++ {
		// attempt to fetch the base page
		bodyStr, statusCode, _ := getRequest(ipLoginURL, client, nil)
		if statusCode == 0 {
			return fmt.Errorf("error making login request")
		}

		//either this will have returned a 200OK already or we need to fetch the start page
		if bodyStr == "" {
			if !hasXSRFToken(jar) {
				log.Printf("no token")
				return fmt.Errorf("no token")
			}

			bodyStr, statusCode, _ = getRequest(ipLoginURL, client, nil)
			if statusCode != http.StatusOK {
				return fmt.Errorf("error making start request")
			}
		}

		//if the original request or fetching the start page seems like we're getting the multi-login response...
		if !strings.Contains(bodyStr, "MNU_access_multiLogin2.htm") {
			// we're done
			return nil
		}

		//<form action="multi_login.cgi?id=9332ac608781479872895638968ec5ea84c1e4b0f42f3ca1a16a58ebeb95ccfe" method="POST">
		bodyStr, statusCode, _ = getRequest(ipLoginURL+"/MNU_access_multiLogin2.htm", client, nil)
		if statusCode != http.StatusOK {
			return fmt.Errorf("error making MNU request")
		}
		// Extract the form action from the response
		formActionRegex := regexp.MustCompile(`<form action="multi_login\.cgi\?id=([^"]+)"`)
		log.Printf("bodyStr: %s", bodyStr)
		matches := formActionRegex.FindStringSubmatch(bodyStr)
		if len(matches) < 2 {
			return fmt.Errorf("couldn't find form action in the response")
		}
		id := matches[1]
		log.Printf("Extracted form action: %s", id)

		// Create params as url.Values with id set to id
		params := url.Values{}
		params.Set("yes", "")
		params.Set("act", "yes")

		getRequest(ipLoginURL+"/multi_login.cgi?id="+id, client, &params)
		// Clear all cookies for all URLs from the jar
		jar.SetCookies(nil, nil)
		log.Println("looping")
	}

	return errors.New("exit")
}

func setAuth(req *http.Request) {
	req.SetBasicAuth(config.GetIPUsername, config.GetIPPassword)
	//authHeader := req.Header.Get("Authorization")
	//log.Printf("Authorization Header: %s\n", authHeader)
	//log.Printf("Username: %s, Password: %s\n", config.GetIPUsername, config.GetIPPassword)

	//// Manually create the Basic Auth header to compare with Chrome's
	//manualAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(config.GetIPUsername+":"+config.GetIPPassword))
	//log.Printf("Manually created Authorization Header: %s\n", manualAuth)

	//if authHeader != manualAuth {
	//	log.Printf("Warning: Generated header differs from manual header")
	//	// You might want to use the manual header instead:
	//	// req.Header.Set("Authorization", manualAuth)
	//}
}

func hasXSRFToken(jar *cookiejar.Jar) bool {
	if jar == nil {
		return false
	}

	url, err := url.Parse(ipCheckURL)
	if err != nil {
		log.Printf("Error parsing URL: %v", err)
		return false
	}

	cookies := jar.Cookies(url)
	for _, cookie := range cookies {
		if cookie.Name == "XSRF_TOKEN" {
			log.Printf("XSRF_TOKEN cookie found: %s\n", cookie.Value)
			return true
		}
	}

	return false
}

func getCurrentIP(client *http.Client, jar *cookiejar.Jar) (string, error) {
	if !config.DisableUPnP {
		ip, err := getPublicIPUPnP()
		if err == nil {
			return ip, nil
		}
		log.Printf("UPnP failed, falling back to web-based IP detection: %v", err)
	}

	if !hasXSRFToken(jar) {
		log.Printf("getting token")
		if err := loginAndGetCookie(client, jar); err != nil {
			log.Printf("loginAndGetCookie error: %v", err)
			return "", errors.New("exit")
		}
		log.Printf("got token")
	}

	bodyStr, statusCode, _ := getRequest(ipCheckURL, client, nil)
	if statusCode != http.StatusOK {
		return "", fmt.Errorf("error making request")
	}
	lines := strings.Split(bodyStr, "\n")
	var ipLine string
	foundIPHeader := false
	tdNowrapCount := 0

	for _, line := range lines {
		if strings.Contains(line, "<B>IP Address</B>") {
			foundIPHeader = true
			continue
		}
		if foundIPHeader && strings.Contains(line, "TD NOWRAP") {
			tdNowrapCount++
			if tdNowrapCount == 2 {
				ipLine = line
				break
			}
		}
	}

	if ipLine == "" {
		return "", fmt.Errorf("ip address line not found in response")
	}

	ipRegex := regexp.MustCompile(`\d+\.\d+\.\d+\.\d+`)
	match := ipRegex.FindString(ipLine)
	if match == "" {
		return "", fmt.Errorf("no valid IP address found in the response")
	}

	return match, nil
}

func queryDNS() (string, error) {
	ips, err := net.LookupIP(fqdn)
	if err != nil {
		return "", fmt.Errorf("error looking up IP for %s: %v", fqdn, err)
	}

	for _, ip := range ips {
		if ipv4 := ip.To4(); ipv4 != nil {
			return ipv4.String(), nil
		}
	}

	return "", fmt.Errorf("no IPv4 address found for %s", fqdn)
}

func fetchAPIRecord() (*Record, error) {
	url := fmt.Sprintf("%s/domains/%s/records", nameComAPIURL, config.Domain)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(nameComUsername, config.NameComToken)

	client := &http.Client{
		Timeout: httpTimeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var listResp ListRecordsResponse
	err = json.Unmarshal(body, &listResp)
	if err != nil {
		return nil, err
	}

	for _, record := range listResp.Records {
		if /*record.Type == "A" &&*/ record.Host == config.Host {
			return &record, nil
		}
	}

	return nil, fmt.Errorf("no matching API record found for %s", config.Host)
}

func updateAPIRecord(newIP string, recordID int) error {
	url := fmt.Sprintf("%s/domains/%s/records/%d", nameComAPIURL, config.Domain, recordID)

	payload := map[string]interface{}{
		"host":   config.Host,
		"type":   "A",
		"answer": newIP,
		"ttl":    300,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return err
	}

	req.SetBasicAuth(nameComUsername, config.NameComToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{
		Timeout: httpTimeout,
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("API request failed with status code: %d", resp.StatusCode)
	}

	return nil
}

func getPublicIPUPnP() (string, error) {
	// Discover UPnP devices
	clients, _, err := internetgateway1.NewWANIPConnection1Clients()
	if err != nil {
		return "", fmt.Errorf("UPnP discovery failed: %v", err)
	}
	if len(clients) == 0 {
		return "", fmt.Errorf("no UPnP devices found")
	}

	// Use the first client to get the external IP address
	client := clients[0]
	ip, err := client.GetExternalIPAddress()
	if err != nil {
		return "", fmt.Errorf("failed to get external IP: %v", err)
	}

	return ip, nil
}
