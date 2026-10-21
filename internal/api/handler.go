package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"go-acl-bitmask/pkg/acl"
	"go-acl-bitmask/pkg/auth"
)

// Handler holds the API dependencies and router
type Handler struct {
	evaluator  *acl.Evaluator
	registry   *acl.Registry
	userStore  *auth.UserStore
	sessions   *auth.SessionManager
	contextMgr *auth.ContextManager
}

// NewHandler creates a new HTTP API handler with auth and context manager
func NewHandler(eval *acl.Evaluator) *Handler {
	return &Handler{
		evaluator:  eval,
		registry:   eval.Registry(),
		userStore:  auth.NewUserStore(),
		sessions:   auth.NewSessionManager(),
		contextMgr: auth.NewContextManager(),
	}
}

// CheckRequest is the JSON payload for a single check
type CheckRequest struct {
	ACL     any   `json:"acl"`     // uint64, float64, or hex/decimal string
	Group   int   `json:"group"`   // 1..4 (0 means any matching group)
	Subject uint8 `json:"subject"` // 0..3
	Object  uint8 `json:"object"`  // 0..3
	Right   any   `json:"right"`   // name e.g. "READ", or bitmask 1,2,4,8
	Context uint8 `json:"context"` // active context bitmask
	Raw     bool  `json:"raw"`     // if true, returns plain boolean true/false
}

// BatchCheckRequest is the JSON payload for batch evaluation
type BatchCheckRequest struct {
	ACLs    []any  `json:"acls"`    // slice of uint64 or hex/decimal strings
	Group   int    `json:"group"`   // 1..4 (0 means any)
	Subject uint8  `json:"subject"` // 0..3
	Object  uint8  `json:"object"`  // 0..3
	Right   any    `json:"right"`   // name or bitmask
	Context uint8  `json:"context"` // active context bitmask
	Format  string `json:"format"`  // "bool" (default: [true, false]) or "detailed"
}

// EncodePairRequest defines one group + context pair for encoding
type EncodePairRequest struct {
	PairIndex int   `json:"pair_index"` // 1..4
	Subject   uint8 `json:"subject"`    // 0..3
	Object    uint8 `json:"object"`     // 0..3
	Rights    any   `json:"rights"`     // []string or bitmask uint8
	Context   uint8 `json:"context"`    // 8-bit context requirement
}

// EncodeRequest is the payload to build a 64-bit ACL uint64
type EncodeRequest struct {
	Pairs []EncodePairRequest `json:"pairs"`
}

// DecodeResponse provides a human-readable inspection of a 64-bit ACL
type DecodeResponse struct {
	Uint64 uint64            `json:"uint64"`
	Hex    string            `json:"hex"`
	Binary string            `json:"binary"`
	Pairs  []DecodedPairInfo `json:"pairs"`
}

// DecodedPairInfo details one of the (Gi, Ci) pairs
type DecodedPairInfo struct {
	PairIndex      int      `json:"pair_index"`
	GroupName      string   `json:"group_name"`
	GroupByte      string   `json:"group_byte"`   // e.g. "0x12"
	ContextByte    string   `json:"context_byte"` // e.g. "0x01"
	Subject        uint8    `json:"subject"`
	Object         uint8    `json:"object"`
	RightsMask     uint8    `json:"rights_mask"`
	RightsNames    []string `json:"rights_names"`
	ContextMask    uint8    `json:"context_mask"`
	ActiveInPolicy bool     `json:"active_in_policy"`
}

// LoginRequest defines credentials for authentication
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// SimulateContextRequest defines fake context parameters from client
type SimulateContextRequest struct {
	Location      auth.LocationMode `json:"location"`
	Time          auth.TimeMode     `json:"time"`
	TwoFactorAuth bool              `json:"two_factor_auth"`
	ManagedDevice bool              `json:"managed_device"`
}

// ProfileMatrixResponse returns permission status across all groups for a profile
type ProfileMatrixResponse struct {
	Profile       *auth.Profile         `json:"profile"`
	ActiveContext auth.SimulatedContext `json:"active_context"`
	Groups        []GroupMatrixEntry    `json:"groups"`
}

// GroupMatrixEntry holds rights status for a specific group
type GroupMatrixEntry struct {
	GroupID     int                  `json:"group_id"`
	GroupName   string               `json:"group_name"`
	Subject     uint8                `json:"subject"`
	Object      uint8                `json:"object"`
	HasRights   bool                 `json:"has_rights"`
	ContextReq  uint8                `json:"context_req"`
	ContextMet  bool                 `json:"context_met"`
	RightsCheck []RightCheckItem     `json:"rights_check"`
}

// RightCheckItem holds evaluation for a single right
type RightCheckItem struct {
	Name    string `json:"name"`
	Bit     uint8  `json:"bit"`
	Allowed bool   `json:"allowed"`
	Reason  string `json:"reason"`
}

// RegisterRoutes attaches the API routes to the given ServeMux
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	// ACL Core
	mux.HandleFunc("/api/v1/check", h.HandleCheck)
	mux.HandleFunc("/api/v1/check-batch", h.HandleCheckBatch)
	mux.HandleFunc("/api/v1/encode", h.HandleEncode)
	mux.HandleFunc("/api/v1/decode", h.HandleDecode)
	mux.HandleFunc("/api/v1/groups", h.HandleGroups)

	// Auth & Profiles
	mux.HandleFunc("/api/v1/auth/login", h.HandleLogin)
	mux.HandleFunc("/api/v1/auth/me", h.HandleMe)
	mux.HandleFunc("/api/v1/auth/logout", h.HandleLogout)
	mux.HandleFunc("/api/v1/profiles", h.HandleProfiles)
	mux.HandleFunc("/api/v1/profiles/eval-matrix", h.HandleProfileMatrix)

	// Fake / Spoofed Context Engine
	mux.HandleFunc("/api/v1/context/simulate", h.HandleSimulateContext)
	mux.HandleFunc("/api/v1/context/current", h.HandleCurrentContext)
}

// HandleCheck handles single checks, raw numbers, and array of numbers
func (h *Handler) HandleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil && r.Method == http.MethodPost {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	trimmed := strings.TrimSpace(string(body))

	// Direct JSON Array of numbers: [12345, 67890]
	if strings.HasPrefix(trimmed, "[") {
		var rawList []any
		if err := json.Unmarshal(body, &rawList); err == nil {
			subject := parseUint8Query(r, "subject", 0)
			object := parseUint8Query(r, "object", 0)
			group := parseIntQuery(r, "group", 0)
			context := parseUint8Query(r, "context", h.contextMgr.GetCurrent().ContextByte)
			rightStr := r.URL.Query().Get("right")
			var right any = rightStr
			if rightStr == "" {
				right = 1
			}

			acls := make([]uint64, 0, len(rawList))
			for _, item := range rawList {
				val, err := parseACLNumber(item)
				if err != nil {
					http.Error(w, fmt.Sprintf("invalid ACL number in array: %v", err), http.StatusBadRequest)
					return
				}
				acls = append(acls, val)
			}

			results := h.evaluator.CheckBatchFast(acls, group, subject, object, right, context)
			writeJSON(w, http.StatusOK, results)
			return
		}
	}

	// JSON Object body
	var req CheckRequest
	if len(trimmed) > 0 && strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
	} else if len(trimmed) > 0 && !strings.HasPrefix(trimmed, "{") && !strings.HasPrefix(trimmed, "[") {
		req.ACL = trimmed
	}

	// Merge query parameters for missing fields
	if req.ACL == nil || req.ACL == "" {
		if aclQ := r.URL.Query().Get("acl"); aclQ != "" {
			req.ACL = aclQ
		}
	}
	if req.Subject == 0 && r.URL.Query().Has("subject") {
		req.Subject = parseUint8Query(r, "subject", 0)
	}
	if req.Object == 0 && r.URL.Query().Has("object") {
		req.Object = parseUint8Query(r, "object", 0)
	}
	if req.Group == 0 && r.URL.Query().Has("group") {
		req.Group = parseIntQuery(r, "group", 0)
	}
	if req.Context == 0 {
		if r.URL.Query().Has("context") {
			req.Context = parseUint8Query(r, "context", 0)
		} else {
			// Default to active simulated context
			req.Context = h.contextMgr.GetCurrent().ContextByte
		}
	}
	if req.Right == nil || req.Right == "" {
		if rightQ := r.URL.Query().Get("right"); rightQ != "" {
			req.Right = rightQ
		} else {
			req.Right = 1
		}
	}

	aclVal, err := parseACLNumber(req.ACL)
	if err != nil {
		http.Error(w, "Invalid 'acl' value: "+err.Error(), http.StatusBadRequest)
		return
	}

	res := h.evaluator.Check(aclVal, req.Group, req.Subject, req.Object, req.Right, req.Context)

	if req.Raw || r.URL.Query().Get("raw") == "true" {
		w.Header().Set("Content-Type", "application/json")
		if res.Allowed {
			w.Write([]byte("true\n"))
		} else {
			w.Write([]byte("false\n"))
		}
		return
	}

	writeJSON(w, http.StatusOK, res)
}

// HandleCheckBatch handles lists of numbers and returns lists of true/false
func (h *Handler) HandleCheckBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	trimmed := strings.TrimSpace(string(body))

	var req BatchCheckRequest
	if strings.HasPrefix(trimmed, "[") {
		var rawList []any
		if err := json.Unmarshal(body, &rawList); err != nil {
			http.Error(w, "Invalid JSON array: "+err.Error(), http.StatusBadRequest)
			return
		}
		req.ACLs = rawList
		req.Subject = parseUint8Query(r, "subject", 0)
		req.Object = parseUint8Query(r, "object", 0)
		req.Group = parseIntQuery(r, "group", 0)
		req.Context = parseUint8Query(r, "context", h.contextMgr.GetCurrent().ContextByte)
		req.Right = r.URL.Query().Get("right")
		if req.Right == "" {
			req.Right = 1
		}
	} else {
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		if req.Context == 0 && !r.URL.Query().Has("context") {
			req.Context = h.contextMgr.GetCurrent().ContextByte
		}
	}

	acls := make([]uint64, 0, len(req.ACLs))
	for _, item := range req.ACLs {
		val, err := parseACLNumber(item)
		if err != nil {
			http.Error(w, fmt.Sprintf("invalid ACL number: %v", err), http.StatusBadRequest)
			return
		}
		acls = append(acls, val)
	}

	if req.Format == "detailed" {
		detailed := h.evaluator.CheckBatchDetailed(acls, req.Group, req.Subject, req.Object, req.Right, req.Context)
		writeJSON(w, http.StatusOK, map[string]any{
			"count":   len(detailed),
			"results": detailed,
		})
		return
	}

	bools := h.evaluator.CheckBatchFast(acls, req.Group, req.Subject, req.Object, req.Right, req.Context)
	writeJSON(w, http.StatusOK, bools)
}

// HandleEncode builds a 64-bit ACL from structured pairs
func (h *Handler) HandleEncode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req EncodeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}

	aclVal := acl.ACL(0)
	for _, p := range req.Pairs {
		if p.PairIndex < 1 || p.PairIndex > acl.MaxPairs {
			http.Error(w, fmt.Sprintf("pair_index must be 1..%d", acl.MaxPairs), http.StatusBadRequest)
			return
		}

		rightsMask, err := h.resolveRightsInput(p.PairIndex, p.Rights)
		if err != nil {
			http.Error(w, fmt.Sprintf("error in pair %d rights: %v", p.PairIndex, err), http.StatusBadRequest)
			return
		}

		group := acl.NewGroup(p.Subject, p.Object, rightsMask)
		context := acl.ContextGroup(p.Context)

		var setErr error
		aclVal, setErr = aclVal.SetPair(p.PairIndex, group, context)
		if setErr != nil {
			http.Error(w, setErr.Error(), http.StatusInternalServerError)
			return
		}
	}

	decoded := h.decodeACL(aclVal)
	writeJSON(w, http.StatusOK, decoded)
}

// HandleDecode inspects and breaks down a 64-bit ACL uint64
func (h *Handler) HandleDecode(w http.ResponseWriter, r *http.Request) {
	aclStr := r.URL.Query().Get("acl")
	if aclStr == "" && r.Method == http.MethodPost {
		body, _ := io.ReadAll(r.Body)
		aclStr = strings.TrimSpace(string(body))
	}
	if aclStr == "" {
		http.Error(w, "Missing 'acl' query parameter or body", http.StatusBadRequest)
		return
	}

	val, err := parseACLNumber(aclStr)
	if err != nil {
		http.Error(w, "Invalid 'acl': "+err.Error(), http.StatusBadRequest)
		return
	}

	decoded := h.decodeACL(acl.ACL(val))
	writeJSON(w, http.StatusOK, decoded)
}

// HandleGroups returns the registry metadata
func (h *Handler) HandleGroups(w http.ResponseWriter, r *http.Request) {
	groups := h.registry.AllGroups()
	writeJSON(w, http.StatusOK, groups)
}

// =========================================================================
// AUTHENTICATION HANDLERS
// =========================================================================

// HandleLogin authenticates username and password and returns a session token
func (h *Handler) HandleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid credentials payload", http.StatusBadRequest)
		return
	}

	profile, err := h.userStore.Authenticate(req.Username, req.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	session := h.sessions.CreateSession(profile)

	// Set auth cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "acl_session",
		Value:    session.Token,
		Path:     "/",
		Expires:  session.ExpiresAt,
		HttpOnly: true,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"token":          session.Token,
		"profile":        profile,
		"active_context": h.contextMgr.GetCurrent(),
	})
}

// HandleMe returns the currently logged-in user profile
func (h *Handler) HandleMe(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token == "" {
		// Return anonymous / guest default
		guest, _ := h.userStore.GetProfile("guest")
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated":  false,
			"profile":        guest,
			"active_context": h.contextMgr.GetCurrent(),
		})
		return
	}

	session, ok := h.sessions.GetSession(token)
	if !ok {
		guest, _ := h.userStore.GetProfile("guest")
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated":  false,
			"profile":        guest,
			"active_context": h.contextMgr.GetCurrent(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated":  true,
		"token":          session.Token,
		"profile":        session.Profile,
		"active_context": h.contextMgr.GetCurrent(),
	})
}

// HandleLogout terminates the user session
func (h *Handler) HandleLogout(w http.ResponseWriter, r *http.Request) {
	token := extractToken(r)
	if token != "" {
		h.sessions.DeleteSession(token)
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "acl_session",
		Value:   "",
		Path:    "/",
		Expires: time.Unix(0, 0),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "logged out"})
}

// HandleProfiles returns all registered users and automated background processes
func (h *Handler) HandleProfiles(w http.ResponseWriter, r *http.Request) {
	profiles := h.userStore.AllProfiles()
	writeJSON(w, http.StatusOK, profiles)
}

// HandleProfileMatrix evaluates full permission matrix for a given profile
func (h *Handler) HandleProfileMatrix(w http.ResponseWriter, r *http.Request) {
	profileID := r.URL.Query().Get("id")
	if profileID == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	profile, ok := h.userStore.GetProfile(profileID)
	if !ok {
		http.Error(w, "Profile not found", http.StatusNotFound)
		return
	}

	currentCtx := h.contextMgr.GetCurrent()
	aclVal := acl.ACL(profile.DefaultACL)

	var entries []GroupMatrixEntry
	for i := 1; i <= acl.MaxPairs; i++ {
		g, c, _ := aclVal.GetPair(i)
		gDef, _ := h.registry.GetGroup(i)

		var checks []RightCheckItem
		for _, rd := range gDef.Rights {
			checkRes := h.evaluator.Check(profile.DefaultACL, i, profile.SubjectID, g.Object(), rd.Name, currentCtx.ContextByte)
			checks = append(checks, RightCheckItem{
				Name:    rd.Name,
				Bit:     rd.Bit,
				Allowed: checkRes.Allowed,
				Reason:  checkRes.Reason,
			})
		}

		entries = append(entries, GroupMatrixEntry{
			GroupID:     i,
			GroupName:   gDef.Name,
			Subject:     g.Subject(),
			Object:      g.Object(),
			HasRights:   g.Rights() > 0,
			ContextReq:  c.Raw(),
			ContextMet:  c.Satisfied(currentCtx.ContextByte),
			RightsCheck: checks,
		})
	}

	resp := ProfileMatrixResponse{
		Profile:       profile,
		ActiveContext: currentCtx,
		Groups:        entries,
	}
	writeJSON(w, http.StatusOK, resp)
}

// =========================================================================
// FAKE CONTEXT SIMULATOR HANDLERS ("som også gir falsk context info")
// =========================================================================

// HandleSimulateContext updates spoofed location, time and security settings
func (h *Handler) HandleSimulateContext(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req SimulateContextRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid context simulation request", http.StatusBadRequest)
		return
	}

	newState := h.contextMgr.SetContext(req.Location, req.Time, req.TwoFactorAuth, req.ManagedDevice)
	writeJSON(w, http.StatusOK, newState)
}

// HandleCurrentContext returns current spoofed context state
func (h *Handler) HandleCurrentContext(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.contextMgr.GetCurrent())
}

// =========================================================================
// HELPER METHODS
// =========================================================================

func extractToken(r *http.Request) string {
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}
	if cookie, err := r.Cookie("acl_session"); err == nil {
		return cookie.Value
	}
	return ""
}

func (h *Handler) decodeACL(a acl.ACL) DecodeResponse {
	resp := DecodeResponse{
		Uint64: a.Uint64(),
		Hex:    a.Hex(),
		Binary: a.Binary(),
		Pairs:  make([]DecodedPairInfo, acl.MaxPairs),
	}

	for i := 1; i <= acl.MaxPairs; i++ {
		g, c, _ := a.GetPair(i)
		groupDef, _ := h.registry.GetGroup(i)

		var rightNames []string
		for _, rd := range groupDef.Rights {
			if g.HasRight(rd.Bit) {
				rightNames = append(rightNames, rd.Name)
			}
		}

		resp.Pairs[i-1] = DecodedPairInfo{
			PairIndex:      i,
			GroupName:      groupDef.Name,
			GroupByte:      fmt.Sprintf("0x%02X", g.Raw()),
			ContextByte:    fmt.Sprintf("0x%02X", c.Raw()),
			Subject:        g.Subject(),
			Object:         g.Object(),
			RightsMask:     g.Rights(),
			RightsNames:    rightNames,
			ContextMask:    c.Raw(),
			ActiveInPolicy: g.Rights() > 0,
		}
	}

	return resp
}

func (h *Handler) resolveRightsInput(groupID int, input any) (uint8, error) {
	if input == nil {
		return 0, nil
	}
	switch v := input.(type) {
	case float64:
		return uint8(v) & acl.RightsMask, nil
	case int:
		return uint8(v) & acl.RightsMask, nil
	case uint8:
		return v & acl.RightsMask, nil
	case string:
		bit, _, err := h.registry.ResolveRightBit(groupID, v)
		return bit, err
	case []any:
		var mask uint8
		for _, item := range v {
			bit, _, err := h.registry.ResolveRightBit(groupID, item)
			if err != nil {
				return 0, err
			}
			mask |= bit
		}
		return mask, nil
	case []string:
		var mask uint8
		for _, s := range v {
			bit, _, err := h.registry.ResolveRightBit(groupID, s)
			if err != nil {
				return 0, err
			}
			mask |= bit
		}
		return mask, nil
	default:
		return 0, fmt.Errorf("unsupported rights input type: %T", input)
	}
}

func parseACLNumber(input any) (uint64, error) {
	switch v := input.(type) {
	case uint64:
		return v, nil
	case int64:
		return uint64(v), nil
	case int:
		return uint64(v), nil
	case float64:
		return uint64(v), nil
	case string:
		s := strings.TrimSpace(v)
		s = strings.Trim(s, "\"")
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			return strconv.ParseUint(s[2:], 16, 64)
		}
		if strings.HasPrefix(s, "0b") || strings.HasPrefix(s, "0B") {
			return strconv.ParseUint(s[2:], 2, 64)
		}
		return strconv.ParseUint(s, 10, 64)
	default:
		return 0, fmt.Errorf("cannot parse ACL from type %T", input)
	}
}

func parseUint8Query(r *http.Request, key string, defaultVal uint8) uint8 {
	valStr := r.URL.Query().Get(key)
	if valStr == "" {
		return defaultVal
	}
	v, err := strconv.ParseUint(valStr, 10, 8)
	if err != nil {
		return defaultVal
	}
	return uint8(v)
}

func parseIntQuery(r *http.Request, key string, defaultVal int) int {
	valStr := r.URL.Query().Get(key)
	if valStr == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(valStr)
	if err != nil {
		return defaultVal
	}
	return v
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
