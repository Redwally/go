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

// --- Helpers d'encodage du protocole Minecraft ---

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

// --- Déclencheur Crafty ---

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

// --- Répondeur MOTD / Ping & Kick ---

func handleOfflineHandshake(client net.Conn) {
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))

	// 1. Lire le paquet Handshake
	_, err := readVarInt(client) // Length
	if err != nil {
		return
	}
	packetID, err := readVarInt(client)
	if err != nil || packetID != 0x00 {
		return
	}

	_, err = readVarInt(client) // Protocol Version
	if err != nil {
		return
	}
	hostLen, err := readVarInt(client)
	if err != nil {
		return
	}
	hostBuf := make([]byte, hostLen)
	io.ReadFull(client, hostBuf)

	var port uint16
	binary.Read(client, binary.BigEndian, &port)

	nextState, err := readVarInt(client) // 1 pour Status (Ping), 2 pour Login
	if err != nil {
		return
	}

	// --- ÉTAPE 1 : PING DE LA LISTE DE SERVEURS (Status) ---
	if nextState == 1 {
		// Attendre le paquet Status Request (0x00)
		_, _ = readVarInt(client)
		_, _ = readVarInt(client)

		motd := offlineMOTD
		versionName := "§cFabric Hors Ligne"
		if isStarting {
			motd = "§6[Démarrage...] §eFabric charge, réessaie dans quelques secondes !"
			versionName = "§6Démarrage en cours..."
		}

		iconJson := ""
		if serverFavicon != "" {
			iconJson = fmt.Sprintf(`,"favicon":"%s"`, serverFavicon)
		}

		jsonResponse := fmt.Sprintf(`{
			"version": {"name": "%s", "protocol": 765},
			"players": {"max": 20, "online": 0, "sample": []},
			"description": {"text": "%s"}%s
		}`, versionName, motd, iconJson)

		sendPacket(client, 0x00, writeString(jsonResponse))

		// Lire le paquet Ping et renvoyer Pong
		_, err = readVarInt(client)
		if err == nil {
			pingID, err := readVarInt(client)
			if err == nil && pingID == 0x01 {
				payload := make([]byte, 8)
				io.ReadFull(client, payload)
				sendPacket(client, 0x01, payload)
			}
		}
		return
	}

	// --- ÉTAPE 2 : TENTATIVE DE CONNEXION DU JOUEUR (Login Start) ---
	if nextState == 2 {
		_, _ = readVarInt(client)
		loginPacketID, _ := readVarInt(client)

		username := "Joueur Inconnu"
		if loginPacketID == 0x00 {
			nameLen, err := readVarInt(client)
			if err == nil && nameLen < 32 {
				nameBuf := make([]byte, nameLen)
				io.ReadFull(client, nameBuf)
				username = string(nameBuf)
			}
		}

		playerIP := client.RemoteAddr().String()
		log.Printf("[CONNEXION] Tentative de connexion de [%s] (IP: %s)", username, playerIP)

		isStarting = true
		go triggerStart()

		jsonKick := fmt.Sprintf(`{"text":"%s"}`, disconnectMsg)
		sendPacket(client, 0x00, writeString(jsonKick))
	}
}

// --- Gestionnaire de connexions principal ---

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