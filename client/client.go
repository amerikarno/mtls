package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func main() {
	path, err := os.Getwd()
	if err != nil {
		panic(err)
	}
	var clientPath = path + "/nginx/mtls/client/"
	log.Printf("Current directory: %s", path)
	// โหลด Client Certificate + Private Key
	cert, err := tls.LoadX509KeyPair(clientPath+"client.crt", clientPath+"client.key")
	if err != nil {
		panic(fmt.Errorf("failed to load client cert/key: %v", err))
	}

	var serverPath = path + "/nginx/mtls/server/ca/"
	// โหลด Root CA (สำหรับตรวจสอบ server cert)
	caCert, err := os.ReadFile(serverPath + "ca.crt")
	if err != nil {
		panic(fmt.Errorf("failed to read ca cert: %v", err))
	}

	// เพิ่ม CA เข้าไปใน Cert Pool
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)

	// สร้าง Transport พร้อม mTLS
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert}, // client cert+key
		RootCAs:      caCertPool,              // server CA, removed for public cert
		MinVersion:   tls.VersionTLS12,
	}

	transport := &http.Transport{TLSClientConfig: tlsConfig}
	client := &http.Client{Transport: transport}

	// สร้าง request
	req, err := http.NewRequest("GET", "https://localhost:8080", nil)
	if err != nil {
		panic(fmt.Errorf("failed to create request: %v", err))
	}

	// ส่ง request
	resp, err := client.Do(req)
	if err != nil {
		panic(fmt.Errorf("request failed: %v", err))
	}
	defer resp.Body.Close()

	// แสดงผล
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Println("Status:", resp.Status)
	fmt.Println("Body:", string(body))
}
