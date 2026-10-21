package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"go-acl-bitmask/pkg/acl"
	"go-acl-bitmask/pkg/auth"
)

func setupTestServer() (*Handler, *http.ServeMux) {
	eval := acl.NewEvaluator(acl.DefaultRegistry())
	h := NewHandler(eval)
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	return h, mux
}

func TestHandleCheckJSON(t *testing.T) {
	_, mux := setupTestServer()

	// G1: sub 1, obj 2, READ (0x1), context 0x01
	g1 := acl.NewGroup(1, 2, acl.Right1)
	c1 := acl.ContextGroup(0x01)
	aclVal := acl.BuildACL(acl.Pair{Group: g1, Context: c1})

	// 1. Success check
	reqBody := CheckRequest{
		ACL:     aclVal.Uint64(),
		Group:   1,
		Subject: 1,
		Object:  2,
		Right:   "READ",
		Context: 0x01,
	}
	bodyBytes, _ := json.Marshal(reqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/check", bytes.NewReader(bodyBytes))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var res acl.CheckResult
	json.NewDecoder(rec.Body).Decode(&res)
	if !res.Allowed {
		t.Fatalf("expected allowed true, got false: %s", res.Reason)
	}

	// 2. Raw boolean output test
	reqRaw := httptest.NewRequest(http.MethodPost, "/api/v1/check?raw=true", bytes.NewReader(bodyBytes))
	recRaw := httptest.NewRecorder()
	mux.ServeHTTP(recRaw, reqRaw)

	if recRaw.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recRaw.Code)
	}
	if recRaw.Body.String() != "true\n" {
		t.Fatalf("expected 'true\\n', got '%s'", recRaw.Body.String())
	}
}

func TestHandleCheckBatchDirectArray(t *testing.T) {
	_, mux := setupTestServer()

	g1 := acl.NewGroup(1, 2, acl.Right1)
	c1 := acl.ContextGroup(0x01)
	aclVal := acl.BuildACL(acl.Pair{Group: g1, Context: c1})

	numArray := []uint64{aclVal.Uint64(), 0}
	bodyBytes, _ := json.Marshal(numArray)

	url := "/api/v1/check?group=1&subject=1&object=2&right=READ&context=1"
	req := httptest.NewRequest(http.MethodPost, url, bytes.NewReader(bodyBytes))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var bools []bool
	if err := json.NewDecoder(rec.Body).Decode(&bools); err != nil {
		t.Fatalf("failed to decode JSON response: %v", err)
	}

	if len(bools) != 2 || !bools[0] || bools[1] {
		t.Fatalf("unexpected batch response: %v", bools)
	}
}

func TestHandleLoginAndMe(t *testing.T) {
	_, mux := setupTestServer()

	// 1. Login with valid credentials
	loginBody, _ := json.Marshal(LoginRequest{Username: "admin", Password: "admin123"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("login failed: %d %s", rec.Code, rec.Body.String())
	}

	var loginResp map[string]any
	json.NewDecoder(rec.Body).Decode(&loginResp)
	token, ok := loginResp["token"].(string)
	if !ok || token == "" {
		t.Fatalf("expected token in login response")
	}

	// 2. Query /api/v1/auth/me with bearer token
	meReq := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	meReq.Header.Set("Authorization", "Bearer "+token)
	meRec := httptest.NewRecorder()
	mux.ServeHTTP(meRec, meReq)

	if meRec.Code != http.StatusOK {
		t.Fatalf("auth me failed: %d", meRec.Code)
	}

	var meResp map[string]any
	json.NewDecoder(meRec.Body).Decode(&meResp)
	if meResp["authenticated"] != true {
		t.Fatalf("expected authenticated true")
	}
}

func TestHandleContextSimulation(t *testing.T) {
	_, mux := setupTestServer()

	// Simulate Plant Floor + Day Shift + 2FA
	simReq, _ := json.Marshal(SimulateContextRequest{
		Location:      auth.LocPlantFloor,
		Time:          auth.TimeDayShift,
		TwoFactorAuth: true,
		ManagedDevice: false,
	})

	req := httptest.NewRequest(http.MethodPost, "/api/v1/context/simulate", bytes.NewReader(simReq))
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("simulate failed: %d %s", rec.Code, rec.Body.String())
	}

	var simResp auth.SimulatedContext
	json.NewDecoder(rec.Body).Decode(&simResp)

	// Plant floor is bit 1 (0x02), Work hours is bit 0 (0x01), 2FA is bit 3 (0x08) -> 0x0B (11)
	expectedMask := auth.CtxBitPlantFloor | auth.CtxBitWorkHours | auth.CtxBit2FAVerified
	if simResp.ContextByte != expectedMask {
		t.Fatalf("expected context mask 0x%02X, got 0x%02X", expectedMask, simResp.ContextByte)
	}
}

func TestHandleProfileMatrix(t *testing.T) {
	_, mux := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/profiles/eval-matrix?id=operator", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("profile matrix failed: %d %s", rec.Code, rec.Body.String())
	}

	var matrix ProfileMatrixResponse
	json.NewDecoder(rec.Body).Decode(&matrix)
	if matrix.Profile.ID != "operator" {
		t.Fatalf("expected operator profile, got %s", matrix.Profile.ID)
	}
	if len(matrix.Groups) != 4 {
		t.Fatalf("expected 4 groups in matrix, got %d", len(matrix.Groups))
	}
}
