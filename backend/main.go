package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

// -------------------- GLOBALS --------------------
var db *sql.DB
var mu sync.Mutex
var jwtKey = []byte("supersecretkey")

// WebSocket
var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return r.Header.Get("Origin") == "http://localhost:3000"
	},
}

// -------------------- STRUCTS --------------------
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type Message struct {
	Username  string    `json:"username"`
	Content   string    `json:"content"`
	Room      string    `json:"room"`
	CreatedAt time.Time `json:"createdAt"`
}

type Client struct {
	Conn *websocket.Conn
	Room string
}

var clients = make(map[*Client]bool)
var broadcast = make(chan Message)

// -------------------- MAIN --------------------
func main() {
	// Connect to DB
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://maheshproton:MaheshG1990@localhost:5432/protondb?sslmode=disable"
	}
	var err error
	db, err = sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("DB connection failed:", err)
	}
	defer db.Close()

	// Create tables if not exists
	createTables()

	// HTTP Routes
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/messages", getHistory)
	http.HandleFunc("/ws", handleConnections)
	http.HandleFunc("/rooms", getRooms)
	http.HandleFunc("/users", getUsers)
	http.HandleFunc("/senddm", sendDM)
	http.HandleFunc("/getdms", getDMs)

	go handleMessages() // Broadcast WebSocket messages

	log.Println("✅ Server started on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// -------------------- HELPERS --------------------
func enableCORS(w http.ResponseWriter, r *http.Request) bool {
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:3000")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return true
	}
	return false
}

func createTables() {
	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS users (
		id SERIAL PRIMARY KEY,
		username VARCHAR(50) UNIQUE NOT NULL,
		password TEXT NOT NULL
	)`)

	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS rooms (
		id SERIAL PRIMARY KEY,
		name VARCHAR(100) UNIQUE NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)

	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS messages (
		id SERIAL PRIMARY KEY,
		username VARCHAR(50),
		content TEXT,
		room VARCHAR(50),
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)

	_, _ = db.Exec(`CREATE TABLE IF NOT EXISTS direct_messages (
		id SERIAL PRIMARY KEY,
		sender VARCHAR(50) NOT NULL,
		receiver VARCHAR(50) NOT NULL,
		content TEXT NOT NULL,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
}

// -------------------- REGISTER / LOGIN --------------------
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if enableCORS(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(creds.Password), bcrypt.DefaultCost)
	_, err := db.Exec("INSERT INTO users (username,password) VALUES ($1,$2)", creds.Username, hash)
	if err != nil {
		http.Error(w, "User exists", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "User registered"})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if enableCORS(w, r) {
		return
	}
	var creds Credentials
	if err := json.NewDecoder(r.Body).Decode(&creds); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	var hash string
	if err := db.QueryRow("SELECT password FROM users WHERE username=$1", creds.Username).Scan(&hash); err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}

	if bcrypt.CompareHashAndPassword([]byte(hash), []byte(creds.Password)) != nil {
		http.Error(w, "Invalid password", http.StatusUnauthorized)
		return
	}

	exp := time.Now().Add(24 * time.Hour)
	claims := &Claims{Username: creds.Username, RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(exp)}}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tStr, _ := token.SignedString(jwtKey)

	json.NewEncoder(w).Encode(map[string]string{"token": tStr})
}

// -------------------- ROOMS / USERS --------------------
func getRooms(w http.ResponseWriter, r *http.Request) {
	if enableCORS(w, r) {
		return
	}
	rows, _ := db.Query("SELECT name FROM rooms ORDER BY name")
	defer rows.Close()
	var list []string
	for rows.Next() {
		var n string
		rows.Scan(&n)
		list = append(list, n)
	}
	json.NewEncoder(w).Encode(list)
}

func getUsers(w http.ResponseWriter, r *http.Request) {
	if enableCORS(w, r) {
		return
	}
	rows, _ := db.Query("SELECT username FROM users ORDER BY username")
	defer rows.Close()
	var list []string
	for rows.Next() {
		var u string
		rows.Scan(&u)
		list = append(list, u)
	}
	json.NewEncoder(w).Encode(list)
}

// -------------------- MESSAGES --------------------
func getHistory(w http.ResponseWriter, r *http.Request) {
	if enableCORS(w, r) {
		return
	}
	room := r.URL.Query().Get("room")
	if room == "" {
		room = "general"
	}
	rows, _ := db.Query("SELECT username, content, created_at FROM messages WHERE room=$1 ORDER BY created_at ASC LIMIT 50", room)
	defer rows.Close()
	var msgs []Message
	for rows.Next() {
		var m Message
		rows.Scan(&m.Username, &m.Content, &m.CreatedAt)
		m.Room = room
		msgs = append(msgs, m)
	}
	json.NewEncoder(w).Encode(msgs)
}

// -------------------- DIRECT MESSAGES --------------------
func sendDM(w http.ResponseWriter, r *http.Request) {
	if enableCORS(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid method", http.StatusMethodNotAllowed)
		return
	}

	var dm struct{ Sender, Receiver, Content string }
	if err := json.NewDecoder(r.Body).Decode(&dm); err != nil {
		http.Error(w, "Invalid body", http.StatusBadRequest)
		return
	}

	_, err := db.Exec("INSERT INTO direct_messages (sender,receiver,content) VALUES ($1,$2,$3)", dm.Sender, dm.Receiver, dm.Content)
	if err != nil {
		log.Println(err)
		http.Error(w, "DB insert error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{"message": "DM sent"})
}

func getDMs(w http.ResponseWriter, r *http.Request) {
	if enableCORS(w, r) {
		return
	}
	user1 := r.URL.Query().Get("user1")
	user2 := r.URL.Query().Get("user2")
	rows, _ := db.Query(`SELECT sender, receiver, content, created_at 
		FROM direct_messages 
		WHERE (sender=$1 AND receiver=$2) OR (sender=$2 AND receiver=$1)
		ORDER BY created_at ASC LIMIT 100`, user1, user2)
	defer rows.Close()
	var msgs []Message
	for rows.Next() {
		var m Message
		rows.Scan(&m.Username, &m.Room, &m.Content, &m.CreatedAt)
		msgs = append(msgs, m)
	}
	json.NewEncoder(w).Encode(msgs)
}

// -------------------- WEBSOCKET --------------------
func handleConnections(w http.ResponseWriter, r *http.Request) {
	if enableCORS(w, r) {
		return
	}

	tokenStr := r.URL.Query().Get("token")
	if tokenStr == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	claims := &Claims{}
	token, _ := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) { return jwtKey, nil })
	if token == nil || !token.Valid {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("upgrade:", err)
		return
	}
	defer ws.Close()

	room := r.URL.Query().Get("room")
	if room == "" {
		room = "general"
	}

	_, _ = db.Exec("INSERT INTO rooms (name) VALUES ($1) ON CONFLICT (name) DO NOTHING", room)

	client := &Client{Conn: ws, Room: room}
	mu.Lock()
	clients[client] = true
	mu.Unlock()

	for {
		var msg Message
		if err := ws.ReadJSON(&msg); err != nil {
			log.Println("read:", err)
			mu.Lock()
			delete(clients, client)
			mu.Unlock()
			break
		}
		msg.Username = claims.Username
		msg.Room = room
		msg.CreatedAt = time.Now()

		_, err = db.Exec("INSERT INTO messages (username, content, room, created_at) VALUES ($1,$2,$3,$4)",
			msg.Username, msg.Content, msg.Room, msg.CreatedAt)
		if err != nil {
			log.Println("DB insert:", err)
		}

		broadcast <- msg
	}
}

// -------------------- BROADCAST --------------------
func handleMessages() {
	for {
		msg := <-broadcast
		mu.Lock()
		for client := range clients {
			if client.Room == msg.Room {
				if err := client.Conn.WriteJSON(msg); err != nil {
					log.Println("write:", err)
					client.Conn.Close()
					delete(clients, client)
				}
			}
		}
		mu.Unlock()
	}
}
