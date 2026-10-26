package main

import (
	"crypto/tls"
	"encoding/binary"
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
	offlineMOTD   = getEnv("OFFLINE_MOTD", "§c[Hors Ligne] §fRejoins pour démarrer le serveur")
	serverFavicon = getEnv("SERVER_FAVICON", "")

	isOnline   bool
	isOnlineMu sync.RWMutex
	isStarting bool
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

// --- Encodage / Décodage Protocole Minecraft ---

func readVarInt(r io.Reader) (int, error) {
	var num int
	var count int
	for {
		var b [1]byte
		_, err := r.Read(b[:])
		if err != nil {
			return 0, err
		}
		value := int(b[0] & 0x7F)
		num |= value << (7 * count)
		count++
		if count > 5 {
			return 0, fmt.Errorf("VarInt trop grand")
		}
		if (b[0] & 0x80) == 0 {
			break
		}
	}
	return num, nil
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

func writeString(s string) []byte {
	b := []byte(s)
	return append(writeVarInt(len(b)), b...)
}

func sendPacket(conn net.Conn, packetID byte, data []byte) error {
	body := append([]byte{packetID}, data...)
	length := writeVarInt(len(body))
	_, err := conn.Write(append(length, body...))
	return err
}

// --- API Crafty ---

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

// --- Handshake & MOTD ---

func handleOfflineHandshake(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(4 * time.Second))

	// 1. Handshake Packet
	packetLen, err := readVarInt(client)
	if err != nil || packetLen <= 0 {
		return
	}

	packetID, err := readVarInt(client)
	if err != nil || packetID != 0x00 {
		return
	}

	// Protocol version
	_, err = readVarInt(client)
	if err != nil {
		return
	}

	// Hostname (ex: mc.redwally.fr)
	hostLen, err := readVarInt(client)
	if err != nil || hostLen > 255 {
		return
	}
	hostBuf := make([]byte, hostLen)
	if _, err := io.ReadFull(client, hostBuf); err != nil {
		return
	}

	// Port (uint16)
	var port uint16
	if err := binary.Read(client, binary.BigEndian, &port); err != nil {
		return
	}

	// Next State (1 = Status/Ping, 2 = Login)
	nextState, err := readVarInt(client)
	if err != nil {
		return
	}

	// --- STATE 1 : STATUS / PING ---
	if nextState == 1 {
		_, _ = readVarInt(client) // Packet Length
		_, _ = readVarInt(client) // Packet ID (0x00)

		motd := offlineMOTD
		versionName := "§cFabric Hors Ligne"
		if isStarting {
			motd = "§6[Démarrage...] §eFabric charge, réessaie dans 15s !"
			versionName = "§6Démarrage..."
		}

		iconJson := ""
		if serverFavicon != "" {
			iconJson = fmt.Sprintf(`,"favicon":"%s"`, serverFavicon)
		}

		jsonResponse := fmt.Sprintf(`{"version":{"name":"%s","protocol":765},"players":{"max":20,"online":0},"description":{"text":"%s"}%s}`, versionName, motd, iconJson)

		_ = sendPacket(client, 0x00, writeString(jsonResponse))

		// Traitement du paquet Ping (0x01)
		pLen, err := readVarInt(client)
		if err == nil && pLen > 0 {
			pID, err := readVarInt(client)
			if err == nil && pID == 0x01 {
				payload := make([]byte, 8)
				if _, err := io.ReadFull(client, payload); err == nil {
					_ = sendPacket(client, 0x01, payload)
				}
			}
		}
		return
	}

	// --- STATE 2 : LOGIN (TENTATIVE DE REJOINDRre) ---
	if nextState == 2 {
		_, _ = readVarInt(client)
		loginPacketID, _ := readVarInt(client)

		username := "Joueur"
		if loginPacketID == 0x00 {
			nameLen, err := readVarInt(client)
			if err == nil && nameLen > 0 && nameLen < 32 {
				nameBuf := make([]byte, nameLen)
				_, _ = io.ReadFull(client, nameBuf)
				username = string(nameBuf)
			}
		}

		log.Printf("[CONNEXION] [%s] tente de se connecter via %s", username, client.RemoteAddr())

		isStarting = true
		go triggerStart()

		jsonKick := fmt.Sprintf(`{"text":"%s"}`, disconnectMsg)
		_ = sendPacket(client, 0x00, writeString(jsonKick))
	}
}

func handleConnection(client net.Conn) {
	isOnlineMu.RLock()
	online := isOnline
	isOnlineMu.RUnlock()

	if online {
		target, err := net.Dial("tcp", net.JoinHostPort(targetHost, targetPort))
		if err != nil {
			isOnlineMu.Lock()
			isOnline = false
			isOnlineMu.Unlock()
			client.Close()
			return
		}
		defer target.Close()
		defer client.Close()

		go io.Copy(target, client)
		io.Copy(client, target)
		return
	}

	handleOfflineHandshake(client)
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
					isStarting = false
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