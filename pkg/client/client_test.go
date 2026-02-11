package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	cfg "github.com/conductorone/baton-oracle-fccs/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testConfig creates a test configuration with JWT OAuth settings.
// The serverURL should be the mock server URL that will handle both API and OAuth requests.
func testConfig(serverURL string) *cfg.OracleFccs {
	// SECURITY WARNING: This is a TEST-ONLY private key used exclusively for unit tests.
	// This key is:
	// - Only used with mock HTTP servers that do NOT validate JWT signatures
	// - Never used to authenticate against real Oracle FCCS services
	// - Safe to commit to version control as it has no production value
	// - Should NEVER be used in production code or configuration
	//
	// The mock OAuth server (handleOAuthToken) returns a token without validating the JWT,
	// so this key is only used to test JWT construction, not authentication.
	//
	// This is the well-known test RSA 2048-bit key from RFC 9500, Section 2.1, as used in
	// Go's crypto/rsa/example_test.go. It's a standardized test key that's publicly documented
	// and commonly used in test suites to avoid slow key generation.
	testPrivateKey := `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAsPnoGUOnrpiSqt4XynxA+HRP7S+BSObI6qJ7fQAVSPtRkqso
tWxQYLEYzNEx5ZSHTGypibVsJylvCfuToDTfMul8b/CZjP2Ob0LdpYrNH6l5hvFE
4889FU1nZQF15oVLOpUgA7wGiHuEVawrGfey92UE68mOyUVXGweJIVDdxqdMoPvN
NU49l86BU02vlBiESxOuox+dWmuVV7vfYZ79Toh/LUK43YvJh+rhv4nKuF7iHjVjB
d9s50B6iDjj70HFldzOQ9r8SRI+9NirupPTkF5AKNe6kUhKJ1luB7S27ZkvB3tST
T3P59513VVJvnzOjaA1z6Cz+4+eRvcysqhrRgFlwI9TEwIDAQABAoIBAEEYiyDP2
9vCzx/+52dS3LqnI5BjUuJhXUnc6AWX/PCgVAO+8A+gZRgvct7PtZb0sM6P9ZcLr
weomlGezI53FrL0/6xQaa8bBr/ve/a8155OgcjFo6fZEw3Dz7ra5fbSiPmu4/b/k
vrg+Br1l77J54aun6uUAs1f5B9wW+vbR7tzbT/mxaUeDiBzKpe15GwcvbJtdIVMa
2YErtRjc1/5B255BGVXyvlJv0SIlcIEMsHgnAFOp1ZgQ08aDzvilLq8XVMOahAhP
1O2A3X8hKdXPyrx56IVWE9bS9ptTo+eF6eNl+d7htpKGEZHUxinoQpWEBTv+iOoH
sVunkEJ3vjLP3lyI/57fY0NQ1ECgYEA3RBXAjgvIys2gfU3keImF8e/TprLge1I2
vbWmV2j6rZCg5r/AS0u58pii5CvJ5/T5vfJPNgPBy8B/yRDs+6PJO1GmnlhOkG9J
AIPkv0RBZvR0PMBtbp6nT59Y3yo1lwamBVBfY6rc0sLTzosZh2aGoLzrHNMQFMGa
auORzBFpY5lU50CgYEAzPHl60u5DI6Xgep1vr8QvCUuEesCOgJg8Yh1UqVoY/Sm
Qh6MYAv1I9bLGwrb3WW/7kqIoD61fj0aQV5buVZI2loMomtU9KY5SFIsPV+JuUpy
7/+VE01ZQM5FdY8wiYCQiVZYju9X62Wz5LxMNoz+gT7pwlLCsC4N+R8aoBk404aF
1gum8CgYAJ7VTq7Zj4TFV7Soa/T1eE63k9y8a+kdoYk3BASpCHJ29M5R2KEA7YV9
wrBklHTz8VzSTFTbKHEQ5W5csAhoL5Fo64qoHzFFi3Qx7MHESQb9qHyolHEMNx6Q
dsHUn7rlEnaTTyrXh3ifQtD6C0yTmFXUIS65CW9wKApOrnyKJ9nI0HcuZQKBgQCM
toV6e9VGX4AEfpuHvAAnMYQFgeBiYTkBKltQ66XwozhH63uMMomUmtSG87Sz1Tmr
XadjAhy8gsG6I0pWaN7QgBuFnzQ/HOkwTm+qKw67AsrZt4zeXNwsH7QXHEJCFnCm
qw9QzEoZTrNtHJHpNboBuVnYcoueZEJrP8OnUG3r68UjmopwKBgAqB2KYYMUqAO
vYcBnEfLDmyZv9BTVNHbR2lKkMYqv5LlvDaBxVfilE0692riO4p6BaAdvzXjKeRr
GNEKoHNBpOSfYCOM16NjL8hIZB1CaV3WbT5oY+jp7Mzd5707d56RZOE+ERK2uz/7
JX9VSsM/LbH9pJibd4e8mikDS9ntciqOH/371
-----END RSA PRIVATE KEY-----`
	
	return &cfg.OracleFccs{
		BaseUrl:        serverURL,
		OracleClientId: "test-client-id",
		OracleClientSecret: "test-client-secret",
		TokenUrl:       serverURL + "/oauth2/v1/token",
		JwtPrivateKey:  testPrivateKey,
		JwtSubject:     "test-user",
		JwtKeyId:       "test-key-id",
	}
}

// handleOAuthToken handles mock OAuth token requests for JWT assertion grant type.
// Returns true if the request was an OAuth token request and was handled.
func handleOAuthToken(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/oauth2/v1/token" {
		// Verify it's a JWT assertion request
		// The request should have grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer
		// and Basic Auth header with client credentials
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600}`))
		return true
	}
	return false
}

func TestClient_ListUsers(t *testing.T) {
	// Mock server that returns users via POST /v1/users/list
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OAuth token requests
		if handleOAuthToken(w, r) {
			return
		}

		// Verify the request
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/interop/rest/security/v1/users/list", r.URL.Path)

		// Read and verify request body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var reqBody UsersListRequest
		err = json.Unmarshal(body, &reqBody)
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": 0,
			"details": [
				{"userlogin": "user1", "firstname": "User", "lastname": "One", "email": "user1@example.com"},
				{"userlogin": "user2", "firstname": "User", "lastname": "Two", "email": "user2@example.com"}
			]
		}`))
	}))
	defer server.Close()

	ctx := context.Background()
	client, err := NewClient(ctx, testConfig(server.URL))
	require.NoError(t, err)

	users, rateLimit, err := client.ListUsers(ctx)
	require.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Equal(t, "user1", users[0].UserLogin)
	assert.Equal(t, "User", users[0].FirstName)
	assert.Equal(t, "One", users[0].LastName)
	assert.Equal(t, "user1@example.com", users[0].Email)
	// rateLimit may be nil if mock doesn't return rate limit headers
	_ = rateLimit
}

func TestClient_ListUsers_APIError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OAuth token requests
		if handleOAuthToken(w, r) {
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": 1,
			"error": {
				"errorcode": "EPMCSS-21001",
				"errormessage": "Authorization failed"
			},
			"details": null
		}`))
	}))
	defer server.Close()

	ctx := context.Background()
	client, err := NewClient(ctx, testConfig(server.URL))
	require.NoError(t, err)

	_, _, err = client.ListUsers(ctx)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "EPMCSS-21001")
}

func TestClient_ListGroups(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OAuth token requests
		if handleOAuthToken(w, r) {
			return
		}

		// Verify the request uses POST /v1/groups/list
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/interop/rest/security/v1/groups/list", r.URL.Path)

		// Read and verify request body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var reqBody GroupsListRequest
		err = json.Unmarshal(body, &reqBody)
		require.NoError(t, err)
		assert.True(t, reqBody.Members, "members should be true")
		assert.True(t, reqBody.Roles, "roles should be true")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": 0,
			"details": [
				{
					"groupname": "TestGroup",
					"description": "A test group",
					"type": "EPM",
					"identity": "native://nvid=test123",
					"roles": [{"rolename": "Viewer", "roletype": "Predefined"}],
					"members": {
						"users": [{"userlogin": "user1"}],
						"groups": [{"groupname": "NestedGroup"}]
					}
				}
			]
		}`))
	}))
	defer server.Close()

	client, err := NewClient(context.Background(), testConfig(server.URL))
	require.NoError(t, err)

	groups, _, err := client.ListGroups(context.Background())
	require.NoError(t, err)
	assert.Len(t, groups, 1)
	assert.Equal(t, "TestGroup", groups[0].GroupName)
	assert.Equal(t, "A test group", groups[0].Description)
	assert.Equal(t, "EPM", groups[0].Type)
	assert.Equal(t, "native://nvid=test123", groups[0].Identity)
	assert.Len(t, groups[0].Roles, 1)
	assert.Equal(t, "Viewer", groups[0].Roles[0].RoleName)
	// Verify members are parsed correctly
	require.NotNil(t, groups[0].Members)
	assert.Len(t, groups[0].Members.Users, 1)
	assert.Equal(t, "user1", groups[0].Members.Users[0].UserLogin)
	assert.Len(t, groups[0].Members.Groups, 1)
	assert.Equal(t, "NestedGroup", groups[0].Members.Groups[0].GroupName)
}

func TestClient_GetGroup(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OAuth token requests
		if handleOAuthToken(w, r) {
			return
		}

		// Verify the request uses POST /v1/groups/list with groupname filter
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/interop/rest/security/v1/groups/list", r.URL.Path)

		// Read and verify request body
		body, err := io.ReadAll(r.Body)
		require.NoError(t, err)
		var reqBody GroupsListRequest
		err = json.Unmarshal(body, &reqBody)
		require.NoError(t, err)
		assert.Equal(t, "SpecificGroup", reqBody.GroupName)
		assert.True(t, reqBody.Members, "members should be true")
		assert.True(t, reqBody.Roles, "roles should be true")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": 0,
			"details": [
				{
					"groupname": "SpecificGroup",
					"description": "A specific group",
					"type": "IDCS",
					"identity": "native://nvid=specific123",
					"members": {
						"users": [{"userlogin": "member1"}, {"userlogin": "member2"}],
						"groups": []
					}
				}
			]
		}`))
	}))
	defer server.Close()

	client, err := NewClient(context.Background(), testConfig(server.URL))
	require.NoError(t, err)

	group, _, err := client.GetGroup(context.Background(), "SpecificGroup")
	require.NoError(t, err)
	assert.Equal(t, "SpecificGroup", group.GroupName)
	assert.Equal(t, "A specific group", group.Description)
	assert.Equal(t, "IDCS", group.Type)
	require.NotNil(t, group.Members)
	assert.Len(t, group.Members.Users, 2)
	assert.Equal(t, "member1", group.Members.Users[0].UserLogin)
}

func TestClient_ListRoles(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OAuth token requests
		if handleOAuthToken(w, r) {
			return
		}

		// Verify the request
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/interop/rest/security/v2/role/getavailableroles", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": 0,
			"details": [
				{"name": "Ad Hoc - Create", "id": "HP:0016"},
				{"name": "Viewer", "id": "HUB:004"}
			]
		}`))
	}))
	defer server.Close()

	client, err := NewClient(context.Background(), testConfig(server.URL))
	require.NoError(t, err)

	roles, _, err := client.ListRoles(context.Background())
	require.NoError(t, err)
	assert.Len(t, roles, 2)
	assert.Equal(t, "Ad Hoc - Create", roles[0].Name)
	assert.Equal(t, "HP:0016", roles[0].ID)
	assert.Equal(t, "Viewer", roles[1].Name)
}

func TestClient_GetRoleUserAssignments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OAuth token requests
		if handleOAuthToken(w, r) {
			return
		}

		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/interop/rest/security/v2/report/roleassignmentreport/user", r.URL.Path)
		assert.Equal(t, "Viewer", r.URL.Query().Get("rolename"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": 0,
			"details": [
				{
					"userlogin": "alice",
					"firstname": "Alice",
					"lastname": "Smith",
					"email": "alice@example.com",
					"roles": [{"rolename": "Viewer", "roletype": "Predefined"}]
				},
				{
					"userlogin": "bob",
					"firstname": "Bob",
					"lastname": "Jones",
					"email": "bob@example.com",
					"roles": [{"rolename": "Viewer", "roletype": "Predefined"}]
				}
			]
		}`))
	}))
	defer server.Close()

	client, err := NewClient(context.Background(), testConfig(server.URL))
	require.NoError(t, err)

	users, _, err := client.GetRoleUserAssignments(context.Background(), "Viewer")
	require.NoError(t, err)
	assert.Len(t, users, 2)
	assert.Contains(t, users, "alice")
	assert.Contains(t, users, "bob")
}

func TestClient_GetRoleGroupAssignments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OAuth token requests
		if handleOAuthToken(w, r) {
			return
		}

		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/interop/rest/security/v2/report/roleassignmentreport/group", r.URL.Path)
		assert.Equal(t, "Admin", r.URL.Query().Get("rolename"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": 0,
			"details": [
				{
					"groupname": "AdminGroup",
					"description": "Administrators",
					"type": "EPM",
					"roles": [{"rolename": "Admin", "roletype": "Predefined"}]
				}
			]
		}`))
	}))
	defer server.Close()

	client, err := NewClient(context.Background(), testConfig(server.URL))
	require.NoError(t, err)

	groups, _, err := client.GetRoleGroupAssignments(context.Background(), "Admin")
	require.NoError(t, err)
	assert.Len(t, groups, 1)
	assert.Equal(t, "AdminGroup", groups[0])
}

func TestClient_Authenticate_OAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OAuth token requests
		if r.URL.Path == "/oauth2/v1/token" {
			// Verify OAuth request parameters for JWT assertion
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))
			// JWT assertion requires Basic Auth header
			username, password, ok := r.BasicAuth()
			assert.True(t, ok, "Basic Auth should be present")
			assert.Equal(t, "test-client-id", username)
			assert.Equal(t, "test-client-secret", password)

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte(`{"access_token": "test-token", "token_type": "Bearer", "expires_in": 3600}`))
			return
		}

		t.Errorf("Unexpected request to %s", r.URL.Path)
	}))
	defer server.Close()

	client, err := NewClient(context.Background(), testConfig(server.URL))
	require.NoError(t, err)

	err = client.Authenticate(context.Background())
	assert.NoError(t, err)
}

func TestClient_GetGroupMembers(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OAuth token requests
		if handleOAuthToken(w, r) {
			return
		}

		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/interop/rest/security/v2/report/usergroupreport", r.URL.Path)
		assert.Equal(t, "TestGroup", r.URL.Query().Get("groupname"))

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": 0,
			"details": [
				{
					"userlogin": "alice",
					"firstname": "Alice",
					"lastname": "Smith",
					"email": "alice@example.com",
					"groups": [{"groupname": "TestGroup", "direct": "Yes"}]
				},
				{
					"userlogin": "bob",
					"firstname": "Bob",
					"lastname": "Jones",
					"email": "bob@example.com",
					"groups": [{"groupname": "TestGroup", "direct": "No"}]
				}
			]
		}`))
	}))
	defer server.Close()

	client, err := NewClient(context.Background(), testConfig(server.URL))
	require.NoError(t, err)

	members, _, err := client.GetGroupMembers(context.Background(), "TestGroup")
	require.NoError(t, err)
	assert.Len(t, members, 2)
	assert.Equal(t, "alice", members[0].UserLogin)
	assert.Equal(t, "Alice", members[0].FirstName)
	assert.Len(t, members[0].Groups, 1)
	assert.Equal(t, "TestGroup", members[0].Groups[0].GroupName)
	assert.Equal(t, "Yes", members[0].Groups[0].Direct)
}

func TestClient_GetAllUserRoleAssignments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OAuth token requests
		if handleOAuthToken(w, r) {
			return
		}

		// Verify no rolename filter is passed
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/interop/rest/security/v2/report/roleassignmentreport/user", r.URL.Path)
		assert.Empty(t, r.URL.Query().Get("rolename"), "should not filter by role")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": 0,
			"details": [
				{
					"userlogin": "alice",
					"firstname": "Alice",
					"lastname": "Smith",
					"email": "alice@example.com",
					"roles": [
						{"rolename": "Viewer", "roletype": "Predefined"},
						{"rolename": "User", "roletype": "Predefined"}
					]
				},
				{
					"userlogin": "bob",
					"firstname": "Bob",
					"lastname": "Jones",
					"email": "bob@example.com",
					"roles": [{"rolename": "Admin", "roletype": "Predefined"}]
				}
			]
		}`))
	}))
	defer server.Close()

	client, err := NewClient(context.Background(), testConfig(server.URL))
	require.NoError(t, err)

	assignments, _, err := client.GetAllUserRoleAssignments(context.Background())
	require.NoError(t, err)

	// Alice has Viewer and User roles
	assert.Contains(t, assignments["Viewer"], "alice")
	assert.Contains(t, assignments["User"], "alice")
	// Bob has Admin role
	assert.Contains(t, assignments["Admin"], "bob")
	// Verify counts
	assert.Len(t, assignments["Viewer"], 1)
	assert.Len(t, assignments["Admin"], 1)
}

func TestClient_GetAllGroupRoleAssignments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle OAuth token requests
		if handleOAuthToken(w, r) {
			return
		}

		// Verify no rolename filter is passed
		assert.Equal(t, http.MethodGet, r.Method)
		assert.Equal(t, "/interop/rest/security/v2/report/roleassignmentreport/group", r.URL.Path)
		assert.Empty(t, r.URL.Query().Get("rolename"), "should not filter by role")

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{
			"status": 0,
			"details": [
				{
					"groupname": "AdminGroup",
					"description": "Administrators",
					"type": "EPM",
					"roles": [{"rolename": "Admin", "roletype": "Predefined"}]
				},
				{
					"groupname": "ViewerGroup",
					"description": "Viewers",
					"type": "IDCS",
					"roles": [
						{"rolename": "Viewer", "roletype": "Predefined"},
						{"rolename": "User", "roletype": "Predefined"}
					]
				}
			]
		}`))
	}))
	defer server.Close()

	client, err := NewClient(context.Background(), testConfig(server.URL))
	require.NoError(t, err)

	assignments, _, err := client.GetAllGroupRoleAssignments(context.Background())
	require.NoError(t, err)

	// AdminGroup has Admin role
	assert.Contains(t, assignments["Admin"], "AdminGroup")
	// ViewerGroup has Viewer and User roles
	assert.Contains(t, assignments["Viewer"], "ViewerGroup")
	assert.Contains(t, assignments["User"], "ViewerGroup")
}
