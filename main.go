package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// ==========================
// Models & Types
// ==========================

type Role string

const (
	RoleStaff    Role = "staff"
	RoleApprover Role = "approver"
	RoleAdmin    Role = "admin"
)

type User struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	Password  string `json:"-"` // stored as hash
	Role      Role   `json:"role"`
	APIKey    string `json:"apiKey"`
	CreatedAt int64  `json:"createdAt"`
}

type ItineraryItem struct {
	Type        string  `json:"type"` // flight|hotel|train
	From        string  `json:"from,omitempty"`
	To          string  `json:"to,omitempty"`
	CheckIn     string  `json:"checkIn,omitempty"`
	CheckOut    string  `json:"checkOut,omitempty"`
	Date        string  `json:"date,omitempty"`
	Passengers  int     `json:"passengers,omitempty"`
	BudgetLimit float64 `json:"budgetLimit,omitempty"`
	Notes       string  `json:"notes,omitempty"`
}

type TravelRequestStatus string

const (
	TRPending  TravelRequestStatus = "pending"
	TRApproved TravelRequestStatus = "approved"
	TRRejected TravelRequestStatus = "rejected"
)

type TravelRequest struct {
	ID         string              `json:"id"`
	Requester  string              `json:"requester"` // user id
	Purpose    string              `json:"purpose"`
	Items      []ItineraryItem     `json:"items"`
	Status     TravelRequestStatus `json:"status"`
	History    []string            `json:"history"`
	CreatedAt  int64               `json:"createdAt"`
	UpdatedAt  int64               `json:"updatedAt"`
	ApproverID string              `json:"approverId,omitempty"`
}

type Booking struct {
	ID         string  `json:"id"`
	RequestID  string  `json:"requestId"`
	Type       string  `json:"type"` // flight|hotel|train
	Provider   string  `json:"provider"`
	Amount     float64 `json:"amount"`
	Currency   string  `json:"currency"`
	TicketCode string  `json:"ticketCode"`
	VoucherURL string  `json:"voucherUrl,omitempty"`
	CreatedBy  string  `json:"createdBy"` // user id
	CreatedAt  int64   `json:"createdAt"`
}

type Payment struct {
	ID        string  `json:"id"`
	OrderID   string  `json:"orderId"`
	Amount    float64 `json:"amount"`
	Currency  string  `json:"currency"`
	Status    string  `json:"status"` // created|paid|failed
	CreatedAt int64   `json:"createdAt"`
}

// ==========================
// In-memory Stores (MVP)
// ==========================

var (
	usersMu sync.RWMutex
	users   = map[string]*User{}

	requestsMu sync.RWMutex
	requests   = map[string]*TravelRequest{}

	bookingsMu sync.RWMutex
	bookings   = map[string]*Booking{}

	paymentsMu sync.RWMutex
	payments   = map[string]*Payment{}

	apiKeysMu sync.RWMutex
	apiKeys   = map[string]string{} // apiKey -> userID
)

// ==========================
// Utilities
// ==========================

var jwtSecret = []byte(getEnv("JWT_SECRET", "dev_super_secret_change_me"))

func getEnv(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func now() int64 { return time.Now().Unix() }

func jsonResponse(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func jsonError(w http.ResponseWriter, status int, message string) {
	jsonResponse(w, status, map[string]interface{}{
		"error":   true,
		"message": message,
		"status":  status,
	})
}

func hashPassword(pw string) string {
	h := sha256.Sum256([]byte(pw))
	return base64.StdEncoding.EncodeToString(h[:])
}

func checkPassword(hash, pw string) bool { return hash == hashPassword(pw) }

func secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
		next.ServeHTTP(w, r)
	})
}

// ==========================
// Auth: JWT + API Keys
// ==========================

type Claims struct {
	UserID string `json:"userId"`
	Role   Role   `json:"role"`
	jwt.RegisteredClaims
}

func issueJWT(u *User) (string, error) {
	claims := Claims{
		UserID: u.ID,
		Role:   u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "travel-mvp",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(jwtSecret)
}

func parseJWT(tokenStr string) (*Claims, error) {
	parsed, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		return jwtSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := parsed.Claims.(*Claims); ok && parsed.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

// Require either JWT (Authorization: Bearer <token>) OR API key (X-API-Key)
func authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow only auth endpoints without auth
		if strings.HasPrefix(r.URL.Path, "/api/auth/") {
			next.ServeHTTP(w, r)
			return
		}

		apiKey := r.Header.Get("X-API-Key")
		if apiKey != "" {
			apiKeysMu.RLock()
			uid, ok := apiKeys[apiKey]
			apiKeysMu.RUnlock()
			if ok {
				r.Header.Set("X-User-ID", uid)
				next.ServeHTTP(w, r)
				return
			}
		}

		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			jsonError(w, http.StatusUnauthorized, "missing Authorization or X-API-Key")
			return
		}
		tok := strings.TrimPrefix(auth, "Bearer ")
		claims, err := parseJWT(tok)
		if err != nil {
			jsonError(w, http.StatusUnauthorized, "invalid token")
			return
		}
		r.Header.Set("X-User-ID", claims.UserID)
		r.Header.Set("X-User-Role", string(claims.Role))
		next.ServeHTTP(w, r)
	})
}

func requireRole(roles ...Role) func(http.Handler) http.Handler {
	allowed := map[Role]bool{}
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := Role(r.Header.Get("X-User-Role"))
			if role == "" {
				// If authenticated via API key (no role), allow minimal access (read-only searches)
				next.ServeHTTP(w, r)
				return
			}
			if !allowed[role] {
				jsonError(w, http.StatusForbidden, "forbidden: insufficient role")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ==========================
// Handlers: Auth
// ==========================

type registerReq struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     Role   `json:"role"`
}

type loginReq struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req registerReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Email == "" || req.Password == "" || req.Name == "" || req.Role == "" {
		jsonError(w, http.StatusBadRequest, "missing fields")
		return
	}

	usersMu.Lock()
	defer usersMu.Unlock()
	for _, u := range users {
		if strings.EqualFold(u.Email, req.Email) {
			jsonError(w, http.StatusConflict, "email already registered")
			return
		}
	}
	id := uuid.NewString()
	apiKey := generateAPIKey()
	u := &User{ID: id, Name: req.Name, Email: req.Email, Password: hashPassword(req.Password), Role: req.Role, APIKey: apiKey, CreatedAt: now()}
	users[id] = u

	apiKeysMu.Lock()
	apiKeys[apiKey] = id
	apiKeysMu.Unlock()

	token, _ := issueJWT(u)
	jsonResponse(w, http.StatusCreated, map[string]interface{}{"user": sanitizeUser(u), "token": token, "apiKey": apiKey})
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req loginReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	usersMu.RLock()
	defer usersMu.RUnlock()
	for _, u := range users {
		if strings.EqualFold(u.Email, req.Email) && checkPassword(u.Password, req.Password) {
			tok, _ := issueJWT(u)
			jsonResponse(w, http.StatusOK, map[string]interface{}{"user": sanitizeUser(u), "token": tok, "apiKey": u.APIKey})
			return
		}
	}
	jsonError(w, http.StatusUnauthorized, "invalid credentials")
}

func sanitizeUser(u *User) map[string]interface{} {
	return map[string]interface{}{"id": u.ID, "name": u.Name, "email": u.Email, "role": u.Role, "createdAt": u.CreatedAt}
}

// ==========================
// Handlers: Dashboard
// ==========================
func handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	uid := r.Header.Get("X-User-ID")
	usersMu.RLock()
	u := users[uid]
	usersMu.RUnlock()
	if u == nil {
		jsonError(w, http.StatusUnauthorized, "unknown user")
		return
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{
		"message":    "dashboard",
		"user":       sanitizeUser(u),
		"apiKeyHint": "Use X-API-Key header for developer access",
	})
}

// ==========================
// Handlers: Travel Requests & Approvals
// ==========================

type trCreateReq struct {
	Purpose string          `json:"purpose"`
	Items   []ItineraryItem `json:"items"`
}

func handleTRCreateOrList(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		var req trCreateReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if req.Purpose == "" || len(req.Items) == 0 {
			jsonError(w, http.StatusBadRequest, "purpose/items required")
			return
		}
		uid := r.Header.Get("X-User-ID")
		tr := &TravelRequest{ID: uuid.NewString(), Requester: uid, Purpose: req.Purpose, Items: req.Items, Status: TRPending, CreatedAt: now(), UpdatedAt: now(), History: []string{"created"}}
		requestsMu.Lock()
		requests[tr.ID] = tr
		requestsMu.Unlock()
		jsonResponse(w, http.StatusCreated, tr)
	case http.MethodGet:
		role := Role(r.Header.Get("X-User-Role"))
		uid := r.Header.Get("X-User-ID")
		requestsMu.RLock()
		defer requestsMu.RUnlock()
		list := []*TravelRequest{}
		for _, tr := range requests {
			if role == RoleAdmin || role == RoleApprover || tr.Requester == uid {
				list = append(list, tr)
			}
		}
		jsonResponse(w, http.StatusOK, list)
	default:
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func handleTRGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/travel-request/")
	requestsMu.RLock()
	tr := requests[id]
	requestsMu.RUnlock()
	if tr == nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	role := Role(r.Header.Get("X-User-Role"))
	uid := r.Header.Get("X-User-ID")
	if !(role == RoleAdmin || role == RoleApprover || tr.Requester == uid) {
		jsonError(w, http.StatusForbidden, "forbidden")
		return
	}
	jsonResponse(w, http.StatusOK, tr)
}

func handleTRApprove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	role := Role(r.Header.Get("X-User-Role"))
	if role != RoleApprover && role != RoleAdmin {
		jsonError(w, http.StatusForbidden, "only approver/admin")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/travel-request/")
	id = strings.TrimSuffix(id, "/approve")
	requestsMu.Lock()
	defer requestsMu.Unlock()
	tr := requests[id]
	if tr == nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	tr.Status = TRApproved
	tr.ApproverID = r.Header.Get("X-User-ID")
	tr.UpdatedAt = now()
	tr.History = append(tr.History, "approved")
	jsonResponse(w, http.StatusOK, tr)
}

func handleTRReject(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	role := Role(r.Header.Get("X-User-Role"))
	if role != RoleApprover && role != RoleAdmin {
		jsonError(w, http.StatusForbidden, "only approver/admin")
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/travel-request/")
	id = strings.TrimSuffix(id, "/reject")
	requestsMu.Lock()
	defer requestsMu.Unlock()
	tr := requests[id]
	if tr == nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	tr.Status = TRRejected
	tr.ApproverID = r.Header.Get("X-User-ID")
	tr.UpdatedAt = now()
	tr.History = append(tr.History, "rejected")
	jsonResponse(w, http.StatusOK, tr)
}

// ==========================
// Handlers: Search (Mock Integrations)
// ==========================

func handleFlightsSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	q := r.URL.Query()
	from, to, date := q.Get("from"), q.Get("to"), q.Get("date")
	if from == "" || to == "" || date == "" {
		jsonError(w, http.StatusBadRequest, "from,to,date required")
		return
	}
	results := []map[string]interface{}{
		{"id": uuid.NewString(), "provider": "amadeus", "from": from, "to": to, "date": date, "price": 120.0, "currency": "USD"},
		{"id": uuid.NewString(), "provider": "amadeus", "from": from, "to": to, "date": date, "price": 150.5, "currency": "USD"},
	}
	jsonResponse(w, http.StatusOK, results)
}

func handleHotelsSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	city := r.URL.Query().Get("city")
	if city == "" {
		jsonError(w, http.StatusBadRequest, "city required")
		return
	}
	results := []map[string]interface{}{
		{"id": uuid.NewString(), "provider": "hotelbeds", "city": city, "name": "Hotel Alpha", "price": 80.0, "currency": "USD"},
		{"id": uuid.NewString(), "provider": "hotelbeds", "city": city, "name": "Hotel Beta", "price": 95.0, "currency": "USD"},
	}
	jsonResponse(w, http.StatusOK, results)
}

func handleTrainsSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")
	date := r.URL.Query().Get("date")
	if from == "" || to == "" || date == "" {
		jsonError(w, http.StatusBadRequest, "from,to,date required")
		return
	}
	results := []map[string]interface{}{
		{"id": uuid.NewString(), "provider": "railofy", "from": from, "to": to, "date": date, "price": 15.0, "currency": "USD"},
	}
	jsonResponse(w, http.StatusOK, results)
}

// ==========================
// Handlers: Booking & Tickets (Mock)
// ==========================

type bookReq struct {
	RequestID string  `json:"requestId"`
	OfferID   string  `json:"offerId"`
	Amount    float64 `json:"amount"`
	Currency  string  `json:"currency"`
}

func handleBook(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req bookReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if req.RequestID == "" || req.OfferID == "" || req.Amount <= 0 || req.Currency == "" {
			jsonError(w, http.StatusBadRequest, "missing fields")
			return
		}
		uid := r.Header.Get("X-User-ID")
		b := &Booking{ID: uuid.NewString(), RequestID: req.RequestID, Type: kind, Provider: providerFor(kind), Amount: req.Amount, Currency: req.Currency, TicketCode: randomTicket(kind), CreatedBy: uid, CreatedAt: now()}
		bookingsMu.Lock()
		bookings[b.ID] = b
		bookingsMu.Unlock()
		jsonResponse(w, http.StatusCreated, b)
	}
}

func providerFor(kind string) string {
	switch kind {
	case "flight":
		return "amadeus"
	case "hotel":
		return "hotelbeds"
	case "train":
		return "railofy"
	}
	return "unknown"
}

func randomTicket(kind string) string {
	return strings.ToUpper(kind[:1]) + fmt.Sprintf("-%06d", rand.Intn(1000000))
}

func handleGetTicket(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 4 {
			jsonError(w, http.StatusBadRequest, "invalid path")
			return
		}
		id := parts[3]
		bookingsMu.RLock()
		defer bookingsMu.RUnlock()
		b := bookings[id]
		if b == nil || b.Type != kind {
			jsonError(w, http.StatusNotFound, "not found")
			return
		}
		jsonResponse(w, http.StatusOK, b)
	}
}

// ==========================
// Payments (Mock Razorpay)
// ==========================

type createPaymentReq struct {
	Amount   float64 `json:"amount"`
	Currency string  `json:"currency"`
}

func handlePaymentCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req createPaymentReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, http.StatusBadRequest, "invalid body")
		return
	}
	if req.Amount <= 0 || req.Currency == "" {
		jsonError(w, http.StatusBadRequest, "amount/currency required")
		return
	}
	p := &Payment{ID: uuid.NewString(), OrderID: "razorpay_" + uuid.NewString(), Amount: req.Amount, Currency: req.Currency, Status: "created", CreatedAt: now()}
	paymentsMu.Lock()
	payments[p.ID] = p
	paymentsMu.Unlock()
	jsonResponse(w, http.StatusCreated, p)
}

func handlePaymentWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	// In real life validate signature. Here we accept and mark a payment as paid.
	id := r.URL.Query().Get("paymentId")
	if id == "" {
		jsonError(w, http.StatusBadRequest, "paymentId required")
		return
	}
	paymentsMu.Lock()
	defer paymentsMu.Unlock()
	p := payments[id]
	if p == nil {
		jsonError(w, http.StatusNotFound, "not found")
		return
	}
	p.Status = "paid"
	jsonResponse(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ==========================
// Notifications (Mock Twilio/Email)
// ==========================

type notifyReq struct {
	To      string `json:"to"`
	Subject string `json:"subject,omitempty"`
	Body    string `json:"body"`
}

func handleNotify(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req notifyReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, http.StatusBadRequest, "invalid body")
			return
		}
		if req.To == "" || req.Body == "" {
			jsonError(w, http.StatusBadRequest, "to/body required")
			return
		}
		jsonResponse(w, http.StatusOK, map[string]string{"status": "sent", "channel": kind})
	}
}

// ==========================
// Admin
// ==========================

func handleAdminBookings(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	bookingsMu.RLock()
	defer bookingsMu.RUnlock()
	list := []*Booking{}
	for _, b := range bookings {
		list = append(list, b)
	}
	jsonResponse(w, http.StatusOK, list)
}

func handleAdminTravelCosts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		jsonError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	bookingsMu.RLock()
	defer bookingsMu.RUnlock()
	var total float64
	for _, b := range bookings {
		total += b.Amount
	}
	jsonResponse(w, http.StatusOK, map[string]interface{}{"total": total, "currency": "USD", "count": len(bookings)})
}

// cors

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*") // allow all origins for MVP
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		// Handle preflight request
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ==========================
// Router Setup
// ==========================

func main() {
	rand.Seed(time.Now().UnixNano())
	seedDemoUsers()

	mux := http.NewServeMux()

	// Auth routes (no auth required)
	mux.HandleFunc("/api/auth/register", handleRegister)
	mux.HandleFunc("/api/auth/login", handleLogin)

	// Protected routes
	mux.Handle("/api/user/dashboard", authMiddleware(http.HandlerFunc(handleDashboard)))

	mux.Handle("/api/travel-request", authMiddleware(http.HandlerFunc(handleTRCreateOrList)))
	mux.Handle("/api/travel-request/", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/approve") {
			handleTRApprove(w, r)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/reject") {
			handleTRReject(w, r)
			return
		}
		handleTRGet(w, r)
	})))

	mux.Handle("/api/flights/search", authMiddleware(http.HandlerFunc(handleFlightsSearch)))
	mux.Handle("/api/hotels/search", authMiddleware(http.HandlerFunc(handleHotelsSearch)))
	mux.Handle("/api/trains/search", authMiddleware(http.HandlerFunc(handleTrainsSearch)))

	mux.Handle("/api/flights/book", authMiddleware(requireRole(RoleAdmin)(http.HandlerFunc(handleBook("flight")))))
	mux.Handle("/api/hotels/book", authMiddleware(requireRole(RoleAdmin)(http.HandlerFunc(handleBook("hotel")))))
	mux.Handle("/api/trains/book", authMiddleware(requireRole(RoleAdmin)(http.HandlerFunc(handleBook("train")))))

	mux.Handle("/api/flights/", authMiddleware(http.HandlerFunc(handleGetTicket("flight"))))
	mux.Handle("/api/hotels/", authMiddleware(http.HandlerFunc(handleGetTicket("hotel"))))
	mux.Handle("/api/trains/", authMiddleware(http.HandlerFunc(handleGetTicket("train"))))

	mux.Handle("/api/payments/create", authMiddleware(http.HandlerFunc(handlePaymentCreate)))
	mux.Handle("/api/payments/webhook", authMiddleware(http.HandlerFunc(handlePaymentWebhook)))

	mux.Handle("/api/notifications/email", authMiddleware(http.HandlerFunc(handleNotify("email"))))
	mux.Handle("/api/notifications/sms", authMiddleware(http.HandlerFunc(handleNotify("sms"))))

	mux.Handle("/api/admin/bookings", authMiddleware(requireRole(RoleAdmin)(http.HandlerFunc(handleAdminBookings))))
	mux.Handle("/api/admin/reports/travel-costs", authMiddleware(requireRole(RoleAdmin)(http.HandlerFunc(handleAdminTravelCosts))))

	handler := withCORS(secureHeaders(mux))

	server := &http.Server{
		Addr:         ":7556",
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}
	log.Println("🚀 Go Travel MVP API listening on http://localhost:7556")
	log.Fatal(server.ListenAndServe())
}

// ==========================
// Seed demo users (admin, approver, staff)
// ==========================

func seedDemoUsers() {
	admin := &User{ID: uuid.NewString(), Name: "Admin", Email: "admin@example.com", Password: hashPassword("admin123"), Role: RoleAdmin, APIKey: generateAPIKey(), CreatedAt: now()}
	approver := &User{ID: uuid.NewString(), Name: "Approver", Email: "approver@example.com", Password: hashPassword("approver123"), Role: RoleApprover, APIKey: generateAPIKey(), CreatedAt: now()}
	staff := &User{ID: uuid.NewString(), Name: "Staff", Email: "staff@example.com", Password: hashPassword("staff123"), Role: RoleStaff, APIKey: generateAPIKey(), CreatedAt: now()}

	usersMu.Lock()
	users[admin.ID] = admin
	users[approver.ID] = approver
	users[staff.ID] = staff
	usersMu.Unlock()

	apiKeysMu.Lock()
	apiKeys[admin.APIKey] = admin.ID
	apiKeys[approver.APIKey] = approver.ID
	apiKeys[staff.APIKey] = staff.ID
	apiKeysMu.Unlock()

	log.Println("Seeded demo users:")
	log.Printf(" Admin: %s / password: admin123 / apiKey: %s\n", admin.Email, admin.APIKey)
	log.Printf(" Approver: %s / password: approver123 / apiKey: %s\n", approver.Email, approver.APIKey)
	log.Printf(" Staff: %s / password: staff123 / apiKey: %s\n", staff.Email, staff.APIKey)
}

func generateAPIKey() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
