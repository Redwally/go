package main

import (
	"bytes"
	"crypto/tls"
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

var (
	listenPort    = getEnv("LISTEN_PORT", "25565")
	targetHost    = getEnv("TARGET_HOST", "172.17.0.1")
	targetPort    = getEnv("TARGET_PORT", "25566")
	craftyURL     = strings.TrimRight(getEnv("CRAFTY_URL", "https://172.17.0.1:8443"), "/")
	craftyToken   = strings.TrimPrefix(getEnv("CRAFTY_TOKEN", ""), "Bearer ")
	serverID      = getEnv("CRAFTY_SERVER_ID", "")
	
	// On garde les vrais \\n pour que le JSON Minecraft soit valide
	disconnectMsg = getEnv("DISCONNECT_MESSAGE", "§a[AutoStart]\\n§eOrdre envoyé à Crafty !\\n§fRéessaie dans 15 secondes.")
	offlineMOTD   = getEnv("OFFLINE_MOTD", "§c[Hors Ligne] §fRejoins pour démarrer le serveur")
	serverFavicon = getEnv("SERVER_FAVICON", "")

	isOnline   bool
	isOnlineMu sync.RWMutex
	isStarting bool
	httpClient *http.Client

	// Stats
	stats     ProxyStats
	statsFile = getEnv("STATS_FILE", "stats.json")
)

type PlayerLog struct {
	Username  string    `json:"username"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
}

type ProxyStats struct {
	TotalPings         uint64      `json:"total_pings"`
	TotalStartTriggers uint64      `json:"total_start_triggers"`
	History            []PlayerLog `json:"history"`
	mu                 sync.Mutex
}

// --- ENREGISTREUR DE PAQUETS ---
// Permet de lire le pseudo tout en mémorisant les paquets pour les renvoyer au serveur ensuite
type RecordingConn struct {
	net.Conn
	Buffer bytes.Buffer
	Record bool
}

func (r *RecordingConn) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if r.Record && n > 0 {
		r.Buffer.Write(p[:n])
	}
	return n, err
}

func init() {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	httpClient = &http.Client{Transport: tr, Timeout: 5 * time.Second}

	data, err := os.ReadFile(statsFile)
	if err == nil {
		json.Unmarshal(data, &stats)
	} else {
		stats.History = make([]PlayerLog, 0)
	}
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
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
	allowedList := getEnv("ALLOWED_PLAYERS", "")
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

// --- Handler de Connexion Intelligente ---

func handleConnection(client net.Conn) {
	isMaintenance := strings.EqualFold(getEnv("MAINTENANCE_MODE", "false"), "true")

	isOnlineMu.RLock()
	online := isOnline
	isOnlineMu.RUnlock()

	// 1. Relais natif ULTRA-RAPIDE si le serveur est UP et qu'il n'y a PAS de maintenance
	if online && !isMaintenance {
		target, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, targetPort), 2*time.Second)
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

	// 2. Mode Interception (Serveur hors ligne OU Maintenance active)
	// On wrap la connexion pour enregistrer les paquets qu'on lit
	rc := &RecordingConn{Conn: client, Record: true}
	defer rc.Close()
	rc.SetDeadline(time.Now().Add(4 * time.Second))

	packetLen, err := readVarInt(rc)
	if err != nil || packetLen <= 0 {
		return
	}

	packetID, err := readVarInt(rc)
	if err != nil || packetID != 0x00 {
		return
	}

	_, err = readVarInt(rc) // Protocol version
	if err != nil {
		return
	}

	hostLen, err := readVarInt(rc)
	if err != nil || hostLen > 255 {
		return
	}
	hostBuf := make([]byte, hostLen)
	if _, err := io.ReadFull(rc, hostBuf); err != nil {
		return
	}

	var port uint16
	if err := binary.Read(rc, binary.BigEndian, &port); err != nil {
		return
	}

	nextState, err := readVarInt(rc)
	if err != nil {
		return
	}

	// --- STATE 1 : STATUS / PING ---
	if nextState == 1 {
		stats.mu.Lock()
		stats.TotalPings++
		stats.mu.Unlock()

		_, _ = readVarInt(rc)
		_, _ = readVarInt(rc)

		motd := offlineMOTD
		versionName := "§cFabric Hors Ligne"
		
		if isMaintenance {
			motd = strings.ReplaceAll(getEnv("MAINTENANCE_MESSAGE", "§c[Maintenance]\\n§fLe serveur est fermé."), "\n", "\\n")
			versionName = "§4Maintenance"
		} else if isStarting {
			motd = "§6[Démarrage...] §eFabric charge, réessaie dans 15s !"
			versionName = "§6Démarrage..."
		}

		iconJson := ""
		if serverFavicon != "" {
			iconJson = fmt.Sprintf(`,"favicon":"%s"`, serverFavicon)
		}

		jsonResponse := fmt.Sprintf(`{"version":{"name":"%s","protocol":765},"players":{"max":20,"online":0},"description":{"text":"%s"}%s}`, versionName, motd, iconJson)

		_ = sendPacket(rc, 0x00, writeString(jsonResponse))

		pLen, err := readVarInt(rc)
		if err == nil && pLen > 0 {
			pID, err := readVarInt(rc)
			if err == nil && pID == 0x01 {
				payload := make([]byte, 8)
				if _, err := io.ReadFull(rc, payload); err == nil {
					_ = sendPacket(rc, 0x01, payload)
				}
			}
		}
		return
	}

	// --- STATE 2 : LOGIN (TENTATIVE DE REJOINDRE) ---
	if nextState == 2 {
		_, _ = readVarInt(rc)
		loginPacketID, _ := readVarInt(rc)

		username := "Joueur"
		if loginPacketID == 0x00 {
			nameLen, err := readVarInt(rc)
			if err == nil && nameLen > 0 && nameLen < 32 {
				nameBuf := make([]byte, nameLen)
				_, _ = io.ReadFull(rc, nameBuf)
				username = string(nameBuf)
			}
		}

		log.Printf("[CONNEXION] [%s] tente de se connecter", username)

		// 1. Vérification Maintenance
		if isMaintenance && !isPlayerAllowed(username) {
			log.Printf("[MAINTENANCE] Refusé pour %s (Serveur en Ligne: %v)", username, online)
			logPlayerAction(username, "blocked_maintenance")
			
			mMsg := strings.ReplaceAll(getEnv("MAINTENANCE_MESSAGE", "§c[Maintenance]\\n§fLe serveur est fermé."), "\n", "\\n")
			jsonKick := fmt.Sprintf(`{"text":"%s"}`, mMsg)
			_ = sendPacket(rc, 0x00, writeString(jsonKick))
			return
		}

		// 2. Vérification Whitelist
		if !isPlayerAllowed(username) {
			log.Printf("[WHITELIST] Non autorisé : %s", username)
			logPlayerAction(username, "blocked_whitelist")
			
			jsonKick := `{"text":"§cTu n'es pas dans la whitelist de ce serveur."}`
			_ = sendPacket(rc, 0x00, writeString(jsonKick))
			return
		}

		// 3. ADMIN AUTORISÉ (ou pas de maintenance/whitelist bloquante)
		if online {
			// Le serveur est allumé, on relie l'admin au serveur !
			rc.SetDeadline(time.Time{}) // Retire la limite de temps pour le jeu
			rc.Record = false           // Stop l'enregistrement
			
			target, err := net.DialTimeout("tcp", net.JoinHostPort(targetHost, targetPort), 2*time.Second)
			if err != nil {
				log.Printf("[PROXY] Erreur de relais: %v", err)
				return
			}
			defer target.Close()

			// On "vomit" tout ce qu'on a enregistré (Handshake + Login Start) vers le serveur
			target.Write(rc.Buffer.Bytes())
			
			// Puis on passe en mode transparent
			go io.Copy(target, rc.Conn)
			io.Copy(rc.Conn, target)
			return
		}

		// 4. Si serveur éteint -> Démarrage
		logPlayerAction(username, "start_triggered")
		isStarting = true
		go triggerStart()

		dMsg := strings.ReplaceAll(disconnectMsg, "\n", "\\n")
		jsonKick := fmt.Sprintf(`{"text":"%s"}`, dMsg)
		_ = sendPacket(rc, 0x00, writeString(jsonKick))
	}
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