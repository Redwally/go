package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// Config (lue UNE fois au démarrage)
// ---------------------------------------------------------------------------

type config struct {
	listenPort  string
	targetHost  string
	targetPort  string
	craftyURL   string
	craftyToken string
	serverID    string
	craftyTLSInsecure bool

	disconnectMsg  string
	offlineMOTD    string
	startingMOTD   string
	maintenanceMsg string
	favicon        string

	maintenanceEnv  bool   // MAINTENANCE_MODE=true
	maintenanceFile string // MAINTENANCE_FILE=/data/maintenance -> `touch` = ON, `rm` = OFF (hot toggle)
	allowedPlayers  map[string]struct{}
	allowedIPs      map[string]struct{} // optionnel : en plus du pseudo, restreint par IP

	proxyProtocol bool // PROXY_PROTOCOL=true (le serveur doit le supporter)
	maxConnPerIP  int  // limite de connexions interceptées simultanées par IP (0 = illimité)
	statsFile     string
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvMsg(key, fallback string) string {
	// permet d'écrire \n littéral dans l'env
	return strings.ReplaceAll(getEnv(key, fallback), `\n`, "\n")
}

func getEnvInt(key string, fallback int) int {
	v, err := strconv.Atoi(getEnv(key, ""))
	if err != nil {
		return fallback
	}
	return v
}

func getEnvBool(key string, fallback bool) bool {
	v := strings.ToLower(getEnv(key, ""))
	if v == "" {
		return fallback
	}
	return v == "true" || v == "1" || v == "yes"
}

func parseSet(s string) map[string]struct{} {
	m := make(map[string]struct{})
	for _, p := range strings.Split(s, ",") {
		p = strings.ToLower(strings.TrimSpace(p))
		if p != "" {
			m[p] = struct{}{}
		}
	}
	return m
}

func loadConfig() config {
	return config{
		listenPort:        getEnv("LISTEN_PORT", "25565"),
		targetHost:        getEnv("TARGET_HOST", "172.17.0.1"),
		targetPort:        getEnv("TARGET_PORT", "25566"),
		craftyURL:         strings.TrimRight(getEnv("CRAFTY_URL", "https://172.17.0.1:8443"), "/"),
		craftyToken:       strings.TrimPrefix(getEnv("CRAFTY_TOKEN", ""), "Bearer "),
		serverID:          getEnv("CRAFTY_SERVER_ID", ""),
		craftyTLSInsecure: getEnvBool("CRAFTY_INSECURE_TLS", true), // cert auto-signé Crafty

		disconnectMsg:  getEnvMsg("DISCONNECT_MESSAGE", "§a[AutoStart]\n§eOrdre envoyé à Crafty !\n§fRéessaie dans 15 secondes."),
		offlineMOTD:    getEnvMsg("OFFLINE_MOTD", "§c[Hors Ligne] §fRejoins pour démarrer le serveur"),
		startingMOTD:   getEnvMsg("STARTING_MOTD", "§6[Démarrage...] §eFabric charge, réessaie dans 15s !"),
		maintenanceMsg: getEnvMsg("MAINTENANCE_MESSAGE", "§c[Maintenance]\n§fLe serveur est fermé."),
		favicon:        getEnv("SERVER_FAVICON", ""),

		maintenanceEnv:  getEnvBool("MAINTENANCE_MODE", false),
		maintenanceFile: getEnv("MAINTENANCE_FILE", ""),
		allowedPlayers:  parseSet(getEnv("ALLOWED_PLAYERS", "")),
		allowedIPs:      parseSet(getEnv("ALLOWED_IPS", "")),

		proxyProtocol: getEnvBool("PROXY_PROTOCOL", false),
		maxConnPerIP:  getEnvInt("MAX_CONN_PER_IP", 20),
		statsFile:     getEnv("STATS_FILE", "stats.json"),
	}
}

const (
	startTimeout   = 120 * time.Second // au-delà, on considère le démarrage raté
	interceptLimit = 4 * time.Second
)

// ---------------------------------------------------------------------------
// État global
// ---------------------------------------------------------------------------

var (
	cfg        = loadConfig()
	online     atomic.Bool
	starting   atomic.Bool
	startedAt  atomic.Int64 // unix
	httpClient *http.Client
	lim        = &limiter{m: make(map[string]int)}
)

// ---------------------------------------------------------------------------
// Stats (écriture différée + atomique)
// ---------------------------------------------------------------------------

type PlayerLog struct {
	Username  string    `json:"username"`
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
}

type ProxyStats struct {
	TotalPings         uint64      `json:"total_pings"`
	TotalStartTriggers uint64      `json:"total_start_triggers"`
	History            []PlayerLog `json:"history"`
}

var (
	stats      ProxyStats
	statsMu    sync.Mutex
	statsDirty atomic.Bool
)

func loadStats() {
	data, err := os.ReadFile(cfg.statsFile)
	if err == nil {
		_ = json.Unmarshal(data, &stats)
	}
	if stats.History == nil {
		stats.History = make([]PlayerLog, 0)
	}
}

func saveStats() {
	statsMu.Lock()
	data, err := json.MarshalIndent(stats, "", "  ")
	statsMu.Unlock()
	if err != nil {
		return
	}
	tmp := cfg.statsFile + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}
	_ = os.Rename(tmp, cfg.statsFile)
}

func statsFlushLoop() {
	for range time.Tick(5 * time.Second) {
		if statsDirty.Swap(false) {
			saveStats()
		}
	}
}

func incPings() {
	statsMu.Lock()
	stats.TotalPings++
	statsMu.Unlock()
	statsDirty.Store(true)
}

func logPlayerAction(username, action string) {
	statsMu.Lock()
	if action == "start_triggered" {
		stats.TotalStartTriggers++
	}
	stats.History = append(stats.History, PlayerLog{Username: username, Timestamp: time.Now(), Action: action})
	if n := len(stats.History); n > 50 {
		stats.History = stats.History[n-50:]
	}
	statsMu.Unlock()
	statsDirty.Store(true)
}

// ---------------------------------------------------------------------------
// Limiteur de connexions par IP
// ---------------------------------------------------------------------------

type limiter struct {
	mu  sync.Mutex
	m   map[string]int
	max int
}

func (l *limiter) acquire(ip string) bool {
	if cfg.maxConnPerIP <= 0 {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m[ip] >= cfg.maxConnPerIP {
		return false
	}
	l.m[ip]++
	return true
}

func (l *limiter) release(ip string) {
	if cfg.maxConnPerIP <= 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.m[ip]--
	if l.m[ip] <= 0 {
		delete(l.m, ip)
	}
}

func remoteIP(c net.Conn) string {
	host, _, err := net.SplitHostPort(c.RemoteAddr().String())
	if err != nil {
		return c.RemoteAddr().String()
	}
	return host
}

// ---------------------------------------------------------------------------
// Maintenance / droits
// ---------------------------------------------------------------------------

func isMaintenance() bool {
	if cfg.maintenanceEnv {
		return true
	}
	if cfg.maintenanceFile != "" {
		_, err := os.Stat(cfg.maintenanceFile)
		return err == nil
	}
	return false
}

// NB : le pseudo n'est PAS authentifié par le proxy. Le vrai contrôle reste
// l'online-mode / whitelist du serveur derrière. ALLOWED_IPS ajoute un garde-fou
// côté proxy pour empêcher qu'un usurpateur déclenche le démarrage.
func isPlayerAllowed(username, ip string) bool {
	if _, ok := cfg.allowedPlayers[strings.ToLower(username)]; !ok {
		return false
	}
	if len(cfg.allowedIPs) > 0 {
		if _, ok := cfg.allowedIPs[strings.ToLower(ip)]; !ok {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Protocole Minecraft
// ---------------------------------------------------------------------------

func readVarInt(r io.ByteReader) (int, error) {
	var num uint32
	for i := 0; i < 5; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		num |= uint32(b&0x7F) << (7 * uint(i))
		if b&0x80 == 0 {
			return int(int32(num)), nil
		}
	}
	return 0, errors.New("VarInt trop grand")
}

func writeVarInt(value int) []byte {
	u := uint32(value)
	var buf []byte
	for {
		b := byte(u & 0x7F)
		u >>= 7
		if u != 0 {
			b |= 0x80
		}
		buf = append(buf, b)
		if u == 0 {
			break
		}
	}
	return buf
}

func readString(r *bytes.Reader, max int) (string, error) {
	n, err := readVarInt(r)
	if err != nil {
		return "", err
	}
	if n < 0 || n > max {
		return "", errors.New("string trop longue")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// Lit un paquet complet (length-prefixed) et renvoie son ID + le reste du payload.
func readPacket(br *bufio.Reader) (int, *bytes.Reader, error) {
	n, err := readVarInt(br)
	if err != nil {
		return 0, nil, err
	}
	if n <= 0 || n > 4096 {
		return 0, nil, errors.New("taille de paquet invalide")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(br, buf); err != nil {
		return 0, nil, err
	}
	r := bytes.NewReader(buf)
	id, err := readVarInt(r)
	if err != nil {
		return 0, nil, err
	}
	return id, r, nil
}

func sendPacket(w io.Writer, id int, data []byte) error {
	body := append(writeVarInt(id), data...)
	_, err := w.Write(append(writeVarInt(len(body)), body...))
	return err
}

// Envoie un JSON (échappé correctement) dans un paquet "string".
func sendJSON(w io.Writer, id int, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return sendPacket(w, id, append(writeVarInt(len(b)), b...))
}

type statusResponse struct {
	Version struct {
		Name     string `json:"name"`
		Protocol int    `json:"protocol"`
	} `json:"version"`
	Players struct {
		Max    int `json:"max"`
		Online int `json:"online"`
	} `json:"players"`
	Description struct {
		Text string `json:"text"`
	} `json:"description"`
	Favicon string `json:"favicon,omitempty"`
}

type chatText struct {
	Text string `json:"text"`
}

// ---------------------------------------------------------------------------
// API Crafty
// ---------------------------------------------------------------------------

func triggerStart() {
	url := fmt.Sprintf("%s/api/v2/servers/%s/action/start_server", cfg.craftyURL, cfg.serverID)
	req, err := http.NewRequest(http.MethodPost, url, nil)
	if err != nil {
		starting.Store(false)
		return
	}
	req.Header.Set("Authorization", "Bearer "+cfg.craftyToken)
	req.Header.Set("token", cfg.craftyToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("[CRAFTY] Erreur envoi démarrage: %v", err)
		starting.Store(false) // permet de retenter
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	if resp.StatusCode >= 300 {
		log.Printf("[CRAFTY] Démarrage refusé (HTTP %d)", resp.StatusCode)
		starting.Store(false)
		return
	}
	log.Println("[CRAFTY] Ordre de démarrage accepté par Crafty")
}

func checkTarget() bool {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(cfg.targetHost, cfg.targetPort), 800*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Surveille le serveur dans les deux sens (UP -> DOWN et DOWN -> UP).
func monitor() {
	fails := 0
	for {
		up := checkTarget()
		switch {
		case up:
			fails = 0
			if !online.Swap(true) {
				starting.Store(false)
				log.Println("[PROXY] Serveur EN LIGNE ! Mode relais TCP natif actif.")
			}
		case online.Load():
			fails++
			if fails >= 2 { // tolère un hoquet
				online.Store(false)
				starting.Store(false)
				fails = 0
				log.Println("[PROXY] Serveur HORS LIGNE détecté, retour en mode interception.")
			}
		default:
			if starting.Load() && time.Since(time.Unix(startedAt.Load(), 0)) > startTimeout {
				starting.Store(false)
				log.Println("[PROXY] Timeout de démarrage, un nouveau start pourra être envoyé.")
			}
		}

		if online.Load() {
			time.Sleep(5 * time.Second)
		} else {
			time.Sleep(2 * time.Second)
		}
	}
}

// ---------------------------------------------------------------------------
// Relais TCP
// ---------------------------------------------------------------------------

func dialTarget() (net.Conn, error) {
	return net.DialTimeout("tcp", net.JoinHostPort(cfg.targetHost, cfg.targetPort), 2*time.Second)
}

// Header PROXY v1 (optionnel) + octets déjà lus à rejouer vers le serveur.
func buildPrefix(c net.Conn, replay []byte) []byte {
	var out []byte
	if cfg.proxyProtocol {
		src, ok1 := c.RemoteAddr().(*net.TCPAddr)
		dst, ok2 := c.LocalAddr().(*net.TCPAddr)
		if ok1 && ok2 {
			proto := "TCP6"
			if src.IP.To4() != nil && dst.IP.To4() != nil {
				proto = "TCP4"
			}
			out = []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", proto, src.IP, dst.IP, src.Port, dst.Port))
		}
	}
	return append(out, replay...)
}

// Relais bidirectionnel : dès qu'un sens se termine, on ferme tout (pas de fuite).
func relay(client, target net.Conn, prefix []byte) {
	defer client.Close()
	defer target.Close()

	if len(prefix) > 0 {
		if _, err := target.Write(prefix); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(target, client)
	go cp(client, target)
	<-done
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

func handleConnection(client net.Conn) {
	maint := isMaintenance()

	// 1. Chemin rapide : serveur UP et pas de maintenance -> relais brut
	if online.Load() && !maint {
		target, err := dialTarget()
		if err == nil {
			relay(client, target, buildPrefix(client, nil))
			return
		}
		online.Store(false) // le monitor confirmera ; on passe en interception
	}

	// 2. Interception (serveur éteint OU maintenance)
	defer client.Close()

	ip := remoteIP(client)
	if !lim.acquire(ip) {
		return
	}
	defer lim.release(ip)

	_ = client.SetDeadline(time.Now().Add(interceptLimit))

	// Tout ce qui est lu sur la socket est copié dans rec -> rejouable vers le serveur
	var rec bytes.Buffer
	br := bufio.NewReader(io.TeeReader(client, &rec))

	// Handshake
	id, r, err := readPacket(br)
	if err != nil || id != 0x00 {
		return
	}
	protocol, err := readVarInt(r)
	if err != nil {
		return
	}
	if _, err = readString(r, 255); err != nil { // host
		return
	}
	if _, err = r.Seek(2, io.SeekCurrent); err != nil { // port
		return
	}
	nextState, err := readVarInt(r)
	if err != nil {
		return
	}

	switch nextState {
	case 1:
		handleStatus(client, br, protocol, maint)
	case 2:
		handleLogin(client, br, &rec, ip, maint)
	}
}

func handleStatus(client net.Conn, br *bufio.Reader, protocol int, maint bool) {
	incPings()

	// Status Request (vide)
	if id, _, err := readPacket(br); err != nil || id != 0x00 {
		return
	}

	motd, versionName := cfg.offlineMOTD, "§cFabric Hors Ligne"
	if maint {
		motd, versionName = cfg.maintenanceMsg, "§4Maintenance"
	} else if starting.Load() {
		motd, versionName = cfg.startingMOTD, "§6Démarrage..."
	}

	var resp statusResponse
	resp.Version.Name = versionName
	resp.Version.Protocol = protocol // on renvoie la version du client -> pas de "incompatible"
	resp.Players.Max = 20
	resp.Description.Text = motd
	resp.Favicon = cfg.favicon

	if err := sendJSON(client, 0x00, resp); err != nil {
		return
	}

	// Ping / Pong
	id, r, err := readPacket(br)
	if err != nil || id != 0x01 {
		return
	}
	payload := make([]byte, 8)
	if _, err := io.ReadFull(r, payload); err == nil {
		_ = sendPacket(client, 0x01, payload)
	}
}

func handleLogin(client net.Conn, br *bufio.Reader, rec *bytes.Buffer, ip string, maint bool) {
	username := "Joueur"
	if id, r, err := readPacket(br); err == nil && id == 0x00 {
		if name, err := readString(r, 32); err == nil && name != "" {
			username = name
		}
	}
	log.Printf("[CONNEXION] %q (%s) tente de se connecter", username, ip)

	// Maintenance
	if maint {
		if !isPlayerAllowed(username, ip) {
			log.Printf("[MAINTENANCE] Refusé pour %q (serveur en ligne: %v)", username, online.Load())
			logPlayerAction(username, "blocked_maintenance")
			_ = sendJSON(client, 0x00, chatText{Text: cfg.maintenanceMsg})
			return
		}
		log.Printf("[MAINTENANCE] %q est admin, bypass autorisé.", username)
	}

	// Serveur en ligne (admin qui bypass, ou serveur devenu UP entre-temps) -> relais
	if online.Load() {
		target, err := dialTarget()
		if err != nil {
			log.Printf("[PROXY] Erreur de relais: %v", err)
			return
		}
		_ = client.SetDeadline(time.Time{})
		replay := append([]byte(nil), rec.Bytes()...)
		relay(client, target, buildPrefix(client, replay))
		return
	}

	// Serveur éteint -> démarrage (une seule fois tant qu'il démarre)
	if starting.CompareAndSwap(false, true) {
		startedAt.Store(time.Now().Unix())
		logPlayerAction(username, "start_triggered")
		go triggerStart()
	} else {
		log.Printf("[PROXY] Démarrage déjà en cours, pas de nouvel ordre (%q)", username)
	}
	_ = sendJSON(client, 0x00, chatText{Text: cfg.disconnectMsg})
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	httpClient = &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.craftyTLSInsecure}},
		Timeout:   5 * time.Second,
	}
	loadStats()

	go monitor()
	go statsFlushLoop()

	// Sauvegarde des stats à l'arrêt (docker stop = SIGTERM)
	go func() {
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
		<-ch
		saveStats()
		os.Exit(0)
	}()

	listener, err := net.Listen("tcp", ":"+cfg.listenPort)
	if err != nil {
		log.Fatalf("Erreur binding port: %v", err)
	}
	defer listener.Close()

	log.Printf("[INIT] Proxy Go démarré sur :%s -> %s:%s", cfg.listenPort, cfg.targetHost, cfg.targetPort)

	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(50 * time.Millisecond) // évite la boucle folle (ex: too many open files)
			continue
		}
		go handleConnection(conn)
	}
}