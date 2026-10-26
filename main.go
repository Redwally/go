package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
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

// --- STRUCTURES & STATISTIQUES ---

type PlayerLog struct {
	Username  string    `json:"username"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"` // "start_triggered", "blocked_maintenance", "blocked_whitelist"
}

type ProxyStats struct {
	TotalPings         uint64      `json:"total_pings"`
	TotalStartTriggers uint64      `json:"total_start_triggers"`
	History            []PlayerLog `json:"history"`
	mu                 sync.Mutex
}

var (
	stats         ProxyStats
	statsFile     string
	serverFavicon string
)

// --- INITIALISATION DES STATS ET FAVICON ---

func initStats() {
	statsFile = os.Getenv("STATS_FILE")
	if statsFile == "" {
		statsFile = "stats.json"
	}

	data, err := os.ReadFile(statsFile)
	if err == nil {
		_ = json.Unmarshal(data, &stats)
		log.Printf("[STATS] Statistiques chargées depuis %s", statsFile)
	} else {
		stats.History = make([]PlayerLog, 0)
		log.Println("[STATS] Fichier de statistiques initialisé.")
	}
}

func loadFavicon() {
	envFav := os.Getenv("SERVER_FAVICON")
	if envFav != "" {
		serverFavicon = envFav
		log.Println("[FAVICON] Icône chargée depuis la variable d'environnement.")
		return
	}

	fileData, err := os.ReadFile("server-icon.png")
	if err != nil {
		log.Printf("[FAVICON] Aucun fichier server-icon.png trouvé : %v", err)
		return
	}
	serverFavicon = "data:image/png;base64," + base64.StdEncoding.EncodeToString(fileData)
	log.Println("[FAVICON] Icône chargée depuis server-icon.png !")
}

func logPlayerAction(username, action string) {
	stats.mu.Lock()
	defer stats.mu.Unlock()

	if action == "start_triggered" {
		stats.TotalStartTriggers++
	}

	entry := PlayerLog{
		Username:  username,
		Timestamp: time.Now(),
		Action:    action,
	}
	stats.History = append(stats.History, entry)
	if len(stats.History) > 50 {
		stats.History = stats.History[1:]
	}

	bytesData, err := json.MarshalIndent(stats, "", "  ")
	if err == nil {
		_ = os.WriteFile(statsFile, bytesData, 0644)
	}
}

func isPlayerAllowed(username string) bool {
	allowedList := os.Getenv("ALLOWED_PLAYERS")
	if allowedList == "" {
		return true
	}

	players := strings.Split(allowedList, ",")
	for _, p := range players {
		if strings.EqualFold(strings.TrimSpace(p), strings.TrimSpace(username)) {
			return true
		}
	}
	return false
}

// --- LOGIQUE PROTOCOLE MINECRAFT (VARINT & PACKETS) ---

func readVarInt(r io.Reader) (int, error) {
	var num int
	var count int
	buf := make([]byte, 1)

	for {
		_, err := r.Read(buf)
		if err != nil {
			return 0, err
		}
		b := buf[0]
		value := int(b & 0x7F)
		num |= value << (7 * count)
		count++
		if count > 5 {
			return 0, fmt.Errorf("varint trop grand")
		}
		if (b & 0x80) == 0 {
			break
		}
	}
	return num, nil
}

func writeVarInt(w io.Writer, value int) error {
	for {
		b := byte(value & 0x7F)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		_, err := w.Write([]byte{b})
		if err != nil {
			return err
		}
		if value == 0 {
			break
		}
	}
	return nil
}

func writeString(w io.Writer, s string) error {
	bytesStr := []byte(s)
	if err := writeVarInt(w, len(bytesStr)); err != nil {
		return err
	}
	_, err := w.Write(bytesStr)
	return err
}

func sendPacket(w io.Writer, packetID int, payload []byte) error {
	var pBuf bytes.Buffer
	_ = writeVarInt(&pBuf, packetID)
	pBuf.Write(payload)

	var frame bytes.Buffer
	_ = writeVarInt(&frame, pBuf.Len())
	frame.Write(pBuf.Bytes())

	_, err := w.Write(frame.Bytes())
	return err
}

func sendKickPacket(conn net.Conn, message string) {
	cleanMsg := strings.ReplaceAll(message, "\\n", "\n")
	jsonEscaped := strings.ReplaceAll(cleanMsg, "\n", "\\n")

	jsonMsg := fmt.Sprintf(`{"text": "%s"}`, jsonEscaped)

	var payload bytes.Buffer
	_ = writeString(&payload, jsonMsg)
	_ = sendPacket(conn, 0x00, payload.Bytes())
}

func extractUsername(r io.Reader) (string, error) {
	strLen, err := readVarInt(r)
	if err != nil || strLen > 16 || strLen < 3 {
		return "Inconnu", err
	}
	buf := make([]byte, strLen)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "Inconnu", err
	}
	return string(buf), nil
}

// --- API CRAFTY CONTROLLER ---

func triggerCraftyStart() {
	craftyURL := os.Getenv("CRAFTY_URL")
	token := os.Getenv("CRAFTY_TOKEN")
	serverID := os.Getenv("CRAFTY_SERVER_ID")

	if craftyURL == "" || token == "" || serverID == "" {
		log.Println("[CRAFTY] Variables d'environnement manquantes.")
		return
	}

	url := fmt.Sprintf("%s/api/v4/servers/%s/action/start", craftyURL, serverID)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		log.Printf("[CRAFTY] Erreur de création de requête: %v", err)
		return
	}

	req.Header.Set("Authorization", token)
	req.Header.Set("Content-Type", "application/json")

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 10 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[CRAFTY] Erreur d'appel API: %v", err)
		return
	}
	defer resp.Body.Close()

	log.Printf("[CRAFTY] Ordre de démarrage envoyé (Status: %d)", resp.StatusCode)
}

// --- PROXY HANDLER ---

func handleConnection(client net.Conn) {
	defer client.Close()

	// 1. Longueur globale du paquet Handshake
	_, err := readVarInt(client)
	if err != nil {
		return
	}

	// 2. Packet ID (0x00)
	packetID, err := readVarInt(client)
	if err != nil || packetID != 0x00 {
		return
	}

	// 3. Version de protocole
	_, _ = readVarInt(client)

	// 4. Hostname
	hostLen, err := readVarInt(client)
	if err != nil || hostLen > 1024 {
		return
	}
	hostBuf := make([]byte, hostLen)
	if _, err := io.ReadFull(client, hostBuf); err != nil {
		return
	}

	// 5. Port
	var port uint16
	_ = binary.Read(client, binary.BigEndian, &port)

	// 6. Next State (1 = Status/Ping, 2 = Login)
	nextState, err := readVarInt(client)
	if err != nil {
		return
	}

	if nextState == 1 {
		// --- STATUS / MOTD ---
		stats.mu.Lock()
		stats.TotalPings++
		stats.mu.Unlock()

		// Paquet Request (0x00)
		_, _ = readVarInt(client)
		_, _ = readVarInt(client)

		var rawMotd string

		// Afficher la maintenance directement dans la liste des serveurs
		if os.Getenv("MAINTENANCE_MODE") == "true" {
			rawMotd = os.Getenv("MAINTENANCE_MESSAGE")
			if rawMotd == "" {
				rawMotd = "§c[Maintenance]\n§fLe serveur est actuellement fermé."
			}
		} else {
			rawMotd = os.Getenv("DISCONNECT_MESSAGE")
			if rawMotd == "" {
				rawMotd = "§aServeur Minecraft\n§eClique pour démarrer !"
			}
		}

		motd := strings.ReplaceAll(rawMotd, "\\n", "\n")

		statusJSON := map[string]interface{}{
			"version": map[string]interface{}{
				"name":     "AutoStart 1.26.3",
				"protocol": 765,
			},
			"players": map[string]interface{}{
				"max":    20,
				"online": 0,
			},
			"description": map[string]interface{}{
				"text": motd,
			},
		}

		if serverFavicon != "" {
			statusJSON["favicon"] = serverFavicon
		}

		jsonBytes, _ := json.Marshal(statusJSON)
		var responsePayload bytes.Buffer
		_ = writeString(&responsePayload, string(jsonBytes))
		_ = sendPacket(client, 0x00, responsePayload.Bytes())

		// Paquet Ping/Pong
		_, err = readVarInt(client)
		if err == nil {
			pID, err := readVarInt(client)
			if err == nil && pID == 0x01 {
				var pingPayload [8]byte
				if _, err := io.ReadFull(client, pingPayload[:]); err == nil {
					_ = sendPacket(client, 0x01, pingPayload[:])
				}
			}
		}
		return
	}

	if nextState == 2 {
		// --- LOGIN START ---
		_, _ = readVarInt(client)
		loginPacketID, err := readVarInt(client)
		if err != nil || loginPacketID != 0x00 {
			return
		}

		username, err := extractUsername(client)
		if err != nil {
			username = "Inconnu"
		}

		// 1. Mode Maintenance
		if os.Getenv("MAINTENANCE_MODE") == "true" && !isPlayerAllowed(username) {
			log.Printf("[MAINTENANCE] Connexion refusée pour %s", username)
			logPlayerAction(username, "blocked_maintenance")

			maintMsg := os.Getenv("MAINTENANCE_MESSAGE")
			if maintMsg == "" {
				maintMsg = "§c[Maintenance]\n§fLe serveur est en cours de maintenance."
			}
			sendKickPacket(client, maintMsg)
			return
		}

		// 2. Whitelist
		if !isPlayerAllowed(username) {
			log.Printf("[WHITELIST] Joueur non autorisé : %s", username)
			logPlayerAction(username, "blocked_whitelist")
			sendKickPacket(client, "§cTu n'es pas dans la whitelist de ce serveur.")
			return
		}

		// 3. Déclenchement Auto-Start
		log.Printf("[AUTOSTART] Lancement du serveur déclenché par : %s", username)
		logPlayerAction(username, "start_triggered")
		triggerCraftyStart()

		msg := os.Getenv("DISCONNECT_MESSAGE")
		if msg == "" {
			msg = "§a[AutoStart]\n§eOrdre de démarrage envoyé !"
		}
		sendKickPacket(client, msg)
	}
}

func main() {
	initStats()
	loadFavicon()

	port := os.Getenv("LISTEN_PORT")
	if port == "" {
		port = "25565"
	}

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("[PROXY] Impossible d'écouter sur le port %s: %v", port, err)
	}
	defer listener.Close()

	log.Printf("[PROXY] En écoute sur le port :%s", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}