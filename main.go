package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	listenPort    = getEnv("LISTEN_PORT", "25565")
	targetHost    = getEnv("TARGET_HOST", "172.17.0.1")
	targetPort    = getEnv("TARGET_PORT", "25566")
	craftyURL     = strings.TrimRight(getEnv("CRAFTY_URL", "https://172.17.0.1:8443"), "/")
	craftyToken   = strings.TrimPrefix(getEnv("CRAFTY_TOKEN", ""), "Bearer ")
	serverID      = getEnv("CRAFTY_SERVER_ID", "")
	disconnectMsg = strings.ReplaceAll(getEnv("DISCONNECT_MESSAGE", "§a[AutoStart]\n§eOrdre envoyé à Crafty !\n§fRéessaie dans 15 secondes."), "\\n", "\n")

	isOnline   bool
	isOnlineMu sync.RWMutex
	httpClient *http.Client
)

func init() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient = &http.Client{Transport: tr, Timeout: 5 * time.Second}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func writeVarInt(value int) []byte {
	var buf []byte
	for {
		b := byte(value & 0x7F)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if value == 0 {
			break
		}
	}
	return buf
}

func sendMinecraftKick(conn net.Conn, message string) {
	jsonMsg := fmt.Sprintf(`{"text":"%s"}`, message)
	strBytes := []byte(jsonMsg)
	strLen := writeVarInt(len(strBytes))

	packetData := append([]byte{0x00}, strLen...) // 0x00 = Disconnect (Login)
	packetData = append(packetData, strBytes...)

	packetLen := writeVarInt(len(packetData))
	fullPacket := append(packetLen, packetData...)

	conn.Write(fullPacket)
}

func triggerStart() {
	url := fmt.Sprintf("%s/api/v2/servers/%s/action/start_server", craftyURL, serverID)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+craftyToken)
	req.Header.Set("token", craftyToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err == nil {
		resp.Body.Close()
		log.Println("[CRAFTY] Ordre de démarrage accepté par Crafty")
	} else {
		log.Printf("[CRAFTY] Erreur envoi démarrage: %v", err)
	}
}

func checkTarget() bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, targetPort), 800*time.Millisecond)
	if err == nil {
		conn.Close()
		return true
	}
	return false
}

func handleConnection(client net.Conn) {
	defer client.Close()

	isOnlineMu.RLock()
	online := isOnline
	isOnlineMu.RUnlock()

	if online {
		target, err := net.Dial("tcp", net.JoinHostPort(targetHost, targetPort))
		if err != nil {
			isOnlineMu.Lock()
			isOnline = false
			isOnlineMu.Unlock()
			return
		}
		defer target.Close()

		go io.Copy(target, client)
		io.Copy(client, target)
		return
	}

	go triggerStart()

	time.Sleep(50 * time.Millisecond)
	sendMinecraftKick(client, disconnectMsg)
}

func main() {
	go func() {
		for {
			isOnlineMu.RLock()
			current := isOnline
			isOnlineMu.RUnlock()

			if !current {
				if checkTarget() {
					isOnlineMu.Lock()
					isOnline = true
					isOnlineMu.Unlock()
					log.Println("[PROXY] Fabric est EN LIGNE ! Mode relais TCP natif actif.")
				}
			}
			time.Sleep(2 * time.Second)
		}
	}()

	listener, err := net.Listen("tcp", ":"+listenPort)
	if err != nil {
		log.Fatalf("Erreur binding port: %v", err)
	}
	defer listener.Close()

	log.Printf("[INIT] Proxy Go démarré sur :%s -> %s:%s", listenPort, targetHost, targetPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}