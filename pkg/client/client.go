package client

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	cfg "github.com/conductorone/baton-oracle-fccs/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const (
	// API endpoints
	// Note: The Oracle EPM Security API has v1 and v2 endpoints.
	// List Users uses v1 (POST), while role/group reports use v2 (GET).
	securityV1Path = "/interop/rest/security/v1"
	securityV2Path = "/interop/rest/security/v2"
	oauthTokenPath = "/HyperionPlanning/rest/v3/oauth/token"
	
	// Provisioning endpoints
	groupsPath  = securityV1Path + "/groups"
	rolesPath   = securityV2Path + "/role"
	
	// Performance and logging thresholds
	maxErrorsToLog = 3
	
	// HTTP client configuration
	defaultHTTPTimeout             = 30 * time.Second
	defaultRateLimit               = 10
	tokenExpiryBuffer              = 1 * time.Minute
	defaultUserExistenceRetries    = 3
	defaultUserExistenceRetryDelay = 2 * time.Second
)

// Client handles HTTP communication with Oracle FCCS REST APIs.
type Client struct {
	config         *cfg.OracleFccs
	baseHttpClient *uhttp.BaseHttpClient
	baseURL        string
	logger         *zap.Logger

	// OAuth2 token management
	accessToken   string
	tokenExpiry   time.Time
	tokenMutex    sync.RWMutex
	oauthTokenURL string
	oauthAudience string

	// JWT assertion settings
	jwtSigner   jose.Signer
	jwtIssuer   string
	jwtSubject  string
	jwtAudience string

	// User existence check configuration
	userExistenceRetries    int
	userExistenceRetryDelay time.Duration
}

// NewClient creates a new Oracle FCCS API client.
func NewClient(ctx context.Context, config *cfg.OracleFccs) (*Client, error) {
	logger := ctxzap.Extract(ctx)
	
	baseURL := strings.TrimSuffix(config.BaseUrl, "/")

	httpClient := &http.Client{Timeout: defaultHTTPTimeout}

	logger.Info("initializing Oracle FCCS client",
		zap.String("base_url", baseURL))

	baseHttpClient, err := uhttp.NewBaseHttpClientWithContext(
		ctx,
		httpClient,
		uhttp.WithRateLimiter(defaultRateLimit, time.Second),
	)
	if err != nil {
		logger.Error("failed to create HTTP client", zap.Error(err))
		return nil, fmt.Errorf("baton-oracle-fccs: error creating HTTP client: %w", err)
	}

	logger.Info("authentication method configured",
		zap.String("method", "oauth_jwt_assertion"))

	client := &Client{
		config:                  config,
		baseHttpClient:          baseHttpClient,
		baseURL:                 baseURL,
		logger:                  logger,
		userExistenceRetries:    defaultUserExistenceRetries,
		userExistenceRetryDelay: defaultUserExistenceRetryDelay,
	}

	// Set OAuth settings (token URL is required)
	client.oauthTokenURL = config.TokenUrl
	client.oauthAudience = baseURL + "/HyperionPlanning/rest"

	// Initialize JWT signer
	signer, issuer, subject, audience, err := buildJWTAssertionSigner(config, client.oauthTokenURL)
	if err != nil {
		return nil, fmt.Errorf("baton-oracle-fccs: error initializing JWT assertion signer: %w", err)
	}
	client.jwtSigner = signer
	client.jwtIssuer = issuer
	client.jwtSubject = subject
	client.jwtAudience = audience

	return client, nil
}

// Authenticate tests the connection by obtaining an OAuth token.
func (c *Client) Authenticate(ctx context.Context) error {
	return c.refreshOAuthToken(ctx)
}

func (c *Client) refreshOAuthToken(ctx context.Context) error {
	startTime := time.Now()

	grantType := "urn:ietf:params:oauth:grant-type:jwt-bearer"
	c.logger.Info("refreshing OAuth token",
		zap.String("grant_type", grantType),
		zap.String("token_url", c.oauthTokenURL))

	// Build JWT assertion
	assertion, err := c.buildJWTAssertion()
	if err != nil {
		return fmt.Errorf("baton-oracle-fccs: failed to build JWT assertion: %w", err)
	}

	// Build form-encoded request body
	data := url.Values{}
	data.Set("grant_type", grantType)
	data.Set("assertion", assertion)
	if c.config.Scope != "" {
		data.Set("scope", c.config.Scope)
	}

	// Parse token URL
	tokenURL, err := url.Parse(c.oauthTokenURL)
	if err != nil {
		return fmt.Errorf("baton-oracle-fccs: error parsing token URL: %w", err)
	}

	// Create request using uhttp
	req, err := c.baseHttpClient.NewRequest(ctx, http.MethodPost, tokenURL,
		uhttp.WithFormBody(data.Encode()),
		uhttp.WithContentTypeFormHeader(),
	)
	if err != nil {
		c.logger.Error("failed to create OAuth token request", zap.Error(err))
		return fmt.Errorf("baton-oracle-fccs: error creating OAuth token request: %w", err)
	}

	// JWT User Assertion requires Basic Auth header for client authentication
	req.SetBasicAuth(c.config.OracleClientId, c.config.OracleClientSecret)

	// Execute request with automatic JSON response handling
	var tokenResp OAuthTokenResponse
	_, err = c.baseHttpClient.Do(req, uhttp.WithJSONResponse(&tokenResp))
	if err != nil {
		c.logger.Error("failed to request OAuth token",
			zap.Error(err),
			zap.String("token_url", c.oauthTokenURL))
		return fmt.Errorf("baton-oracle-fccs: error requesting OAuth token: %w", err)
	}

	c.tokenMutex.Lock()
	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	c.tokenMutex.Unlock()

	duration := time.Since(startTime)
	c.logger.Info("OAuth token refreshed successfully",
		zap.Duration("duration", duration),
		zap.Int("expires_in_seconds", tokenResp.ExpiresIn),
		zap.Time("expires_at", c.tokenExpiry))

	return nil
}

func buildJWTAssertionSigner(cfg *cfg.OracleFccs, tokenURL string) (jose.Signer, string, string, string, error) {
	privateKeyRaw := strings.TrimSpace(cfg.JwtPrivateKey)
	if privateKeyRaw == "" {
		return nil, "", "", "", fmt.Errorf("baton-oracle-fccs: jwt-private-key is required for JWT assertion grant")
	}

	issuer := strings.TrimSpace(cfg.JwtIssuer)
	if issuer == "" {
		issuer = cfg.OracleClientId
	}

	subject := strings.TrimSpace(cfg.JwtSubject)
	if subject == "" {
		return nil, "", "", "", fmt.Errorf("baton-oracle-fccs: jwt-subject is required for JWT assertion grant")
	}

	audience := strings.TrimSpace(cfg.JwtAudience)
	if audience == "" {
		audience = tokenURL
	}

	keyBytes := []byte(privateKeyRaw)
	// Allow base64-encoded PEM for easier env var handling.
	if !strings.Contains(privateKeyRaw, "BEGIN") {
		if decoded, err := base64.StdEncoding.DecodeString(privateKeyRaw); err == nil && len(decoded) > 0 {
			keyBytes = decoded
		}
	}

	privKey, err := parsePrivateKeyPEM(keyBytes)
	if err != nil {
		return nil, "", "", "", err
	}

	opts := (&jose.SignerOptions{}).WithType("JWT")
	if kid := strings.TrimSpace(cfg.JwtKeyId); kid != "" {
		// go-jose does not export a HeaderKeyID constant; use the standard header name directly.
		opts.WithHeader(jose.HeaderKey("kid"), kid)
	}

	// Default to RS256; Oracle Identity Domains typically uses RSA keys for JWT assertion.
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: privKey}, opts)
	if err != nil {
		return nil, "", "", "", err
	}

	return signer, issuer, subject, audience, nil
}

func parsePrivateKeyPEM(pemBytes []byte) (interface{}, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("baton-oracle-fccs: failed to parse jwt-private-key: not valid PEM (or base64 PEM)")
	}

	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("baton-oracle-fccs: failed to parse jwt-private-key: expected RSA private key (PKCS#1 or PKCS#8)")
}

func (c *Client) buildJWTAssertion() (string, error) {
	if c.jwtSigner == nil {
		return "", fmt.Errorf("baton-oracle-fccs: JWT signer not initialized")
	}

	now := time.Now()
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", err
	}
	jti := hex.EncodeToString(jtiBytes)

	claims := josejwt.Claims{
		Issuer:   c.jwtIssuer,
		Subject:  c.jwtSubject,
		Audience: josejwt.Audience{c.jwtAudience},
		IssuedAt: josejwt.NewNumericDate(now),
		Expiry:   josejwt.NewNumericDate(now.Add(5 * time.Minute)),
		ID:       jti,
	}

	return josejwt.Signed(c.jwtSigner).Claims(claims).Serialize()
}

func (c *Client) getAccessToken(ctx context.Context) (string, error) {
	c.tokenMutex.RLock()
	token := c.accessToken
	expiry := c.tokenExpiry
	c.tokenMutex.RUnlock()

	now := time.Now()
	if now.Add(tokenExpiryBuffer).After(expiry) {
		c.logger.Debug("OAuth token expired or expiring soon, refreshing",
			zap.Time("expires_at", expiry),
			zap.Duration("time_until_expiry", time.Until(expiry)))
		
		if err := c.refreshOAuthToken(ctx); err != nil {
			return "", err
		}
		c.tokenMutex.RLock()
		token = c.accessToken
		c.tokenMutex.RUnlock()
	} else {
		c.logger.Debug("using cached OAuth token",
			zap.Duration("time_until_expiry", time.Until(expiry)))
	}

	return token, nil
}

// decodeAPIResponse reads and decodes an API response body into the target struct.
// This helper function standardizes response decoding and reduces code duplication.
func decodeAPIResponse(resp *http.Response, target interface{}) error {
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("baton-oracle-fccs: error reading response body: %w", err)
	}
	
	if err := json.Unmarshal(bodyBytes, target); err != nil {
		return fmt.Errorf("baton-oracle-fccs: error decoding response: %w (body: %s)", err, string(bodyBytes))
	}
	
	return nil
}

// handleGroupNotFoundError verifies if a group exists and returns an appropriate error.
// This helper reduces code duplication in group operation error handling.
func (c *Client) handleGroupNotFoundError(ctx context.Context, groupName, operation string) error {
	exists, verifyErr := c.verifyGroupExists(ctx, groupName)
	if verifyErr != nil {
		if strings.Contains(verifyErr.Error(), "case mismatch") {
			return fmt.Errorf("baton-oracle-fccs: error %s: %w", operation, verifyErr)
		}
		c.logger.Warn("failed to verify group existence",
			zap.Error(verifyErr),
			zap.String("group_name", groupName))
		return nil // Continue with original error
	}
	
	if !exists {
		return fmt.Errorf("baton-oracle-fccs: group '%s' does not exist. Verify the group exists in Oracle FCCS", groupName)
	}
	
	return nil // Group exists, return nil to continue with original error
}


// checkAPIResponseStatusWithLogging checks API response status, logs errors, and returns an appropriate error.
// This is a helper function for cases where we want to log the error before returning it.
func (c *Client) checkAPIResponseStatusWithLogging(apiResp *APIResponse, errorContext map[string]interface{}) error {
	if apiResp.Status != 0 {
		if apiResp.Error != nil {
			logFields := []zap.Field{
				zap.String("error_code", apiResp.Error.ErrorCode),
				zap.String("error_message", apiResp.Error.ErrorMessage),
			}
			for k, v := range errorContext {
				logFields = append(logFields, zap.Any(k, v))
			}
			c.logger.Error("API error", logFields...)
			return fmt.Errorf("baton-oracle-fccs: API error %s: %s", apiResp.Error.ErrorCode, apiResp.Error.ErrorMessage)
		}
		logFields := []zap.Field{
			zap.Int("status", apiResp.Status),
		}
		for k, v := range errorContext {
			logFields = append(logFields, zap.Any(k, v))
		}
		c.logger.Error("API returned non-zero status", logFields...)
		return fmt.Errorf("baton-oracle-fccs: API returned status %d", apiResp.Status)
	}
	return nil
}

// doRequest performs an HTTP request with authentication.
// Returns the rate limit info from the response headers.
func (c *Client) doRequest(ctx context.Context, method, path string, body interface{}, result interface{}) (*v2.RateLimitDescription, error) {
	var fullURL string
	if strings.HasPrefix(path, "http") {
		fullURL = path
	} else {
		fullURL = c.baseURL + path
	}

	parsedURL, err := url.Parse(fullURL)
	if err != nil {
		return nil, fmt.Errorf("baton-oracle-fccs: error parsing URL %s: %w", fullURL, err)
	}

	var reqOpts []uhttp.RequestOption
	reqOpts = append(reqOpts, uhttp.WithAcceptJSONHeader())

	if body != nil {
		reqOpts = append(reqOpts, uhttp.WithJSONBody(body))
	}

	// Get OAuth token
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("baton-oracle-fccs: error getting OAuth token: %w", err)
	}
	reqOpts = append(reqOpts, uhttp.WithBearerToken(token))

	req, err := c.baseHttpClient.NewRequest(ctx, method, parsedURL, reqOpts...)
	if err != nil {
		return nil, fmt.Errorf("baton-oracle-fccs: error creating request: %w", err)
	}

	// Use uhttp DoOptions for response handling
	var rateLimit v2.RateLimitDescription
	doOpts := []uhttp.DoOption{
		uhttp.WithRatelimitData(&rateLimit),
	}
	if result != nil {
		doOpts = append(doOpts, uhttp.WithJSONResponse(result))
	}

	_, err = c.baseHttpClient.Do(req, doOpts...)
	if err != nil {
		return &rateLimit, fmt.Errorf("baton-oracle-fccs: %s %s failed: %w", method, path, err)
	}

	return &rateLimit, nil
}

// ListUsers retrieves all users using POST /interop/rest/security/v1/users/list.
// Note: The Oracle EPM API does not support pagination for this endpoint.
func (c *Client) ListUsers(ctx context.Context) ([]User, *v2.RateLimitDescription, error) {
	// The v1 users/list endpoint uses POST with an optional JSON body
	// Note: We don't request memberof or roles here since we use dedicated reports
	// (User Group Report and Role Assignment Report) for comprehensive grant data
	reqBody := &UsersListRequest{}
	var usersResp UsersResponse

	rateLimit, err := c.doRequest(ctx, "POST", securityV1Path+"/users/list", reqBody, &usersResp)
	if err != nil {
		return nil, rateLimit, fmt.Errorf("baton-oracle-fccs: error listing users: %w", err)
	}

	// Check for API-level errors (status != 0 indicates failure)
	// Note: UsersResponse has the same Status/Error structure as APIResponse
	if err := checkAPIResponseStatus(&APIResponse{Status: usersResp.Status, Error: usersResp.Error}); err != nil {
		return nil, rateLimit, err
	}

	return usersResp.Details, rateLimit, nil
}

// GetUser retrieves a specific user by user login using the list endpoint with a filter.
func (c *Client) GetUser(ctx context.Context, userLogin string) (*User, *v2.RateLimitDescription, error) {
	reqBody := &UsersListRequest{
		UserLogin: userLogin,
		// Note: We don't request memberof or roles here since we use dedicated reports
		// (User Group Report and Role Assignment Report) for comprehensive grant data
	}
	var usersResp UsersResponse

	rateLimit, err := c.doRequest(ctx, "POST", securityV1Path+"/users/list", reqBody, &usersResp)
	if err != nil {
		return nil, rateLimit, fmt.Errorf("baton-oracle-fccs: error getting user %s: %w", userLogin, err)
	}

	if err := checkAPIResponseStatus(&APIResponse{Status: usersResp.Status, Error: usersResp.Error}); err != nil {
		return nil, rateLimit, err
	}

	if len(usersResp.Details) == 0 {
		return nil, rateLimit, fmt.Errorf("baton-oracle-fccs: user %s not found", userLogin)
	}

	return &usersResp.Details[0], rateLimit, nil
}

// ListGroups retrieves all groups using POST /interop/rest/security/v1/groups/list.
// Includes group members and role assignments.
func (c *Client) ListGroups(ctx context.Context) ([]GroupDetail, *v2.RateLimitDescription, error) {
	reqBody := &GroupsListRequest{
		Members: true, // Include user/group members
		Roles:   true, // Include role assignments
	}
	var groupsResp GroupsResponse

	rateLimit, err := c.doRequest(ctx, "POST", securityV1Path+"/groups/list", reqBody, &groupsResp)
	if err != nil {
		return nil, rateLimit, fmt.Errorf("baton-oracle-fccs: error listing groups: %w", err)
	}

	if err := checkAPIResponseStatus(&APIResponse{Status: groupsResp.Status, Error: groupsResp.Error}); err != nil {
		return nil, rateLimit, err
	}

	return groupsResp.Details, rateLimit, nil
}

// GetGroup retrieves a specific group by group name with members.
func (c *Client) GetGroup(ctx context.Context, groupName string) (*GroupDetail, *v2.RateLimitDescription, error) {
	reqBody := &GroupsListRequest{
		GroupName: groupName,
		Members:   true,
		Roles:     true,
	}
	var groupsResp GroupsResponse

	rateLimit, err := c.doRequest(ctx, "POST", securityV1Path+"/groups/list", reqBody, &groupsResp)
	if err != nil {
		return nil, rateLimit, fmt.Errorf("baton-oracle-fccs: error getting group %s: %w", groupName, err)
	}

	if err := checkAPIResponseStatus(&APIResponse{Status: groupsResp.Status, Error: groupsResp.Error}); err != nil {
		return nil, rateLimit, err
	}

	if len(groupsResp.Details) == 0 {
		return nil, rateLimit, fmt.Errorf("baton-oracle-fccs: group %s not found", groupName)
	}

	return &groupsResp.Details[0], rateLimit, nil
}

// ListRoles retrieves available roles using GET /interop/rest/security/v2/role/getavailableroles.
// The optional type parameter can filter by "predefined" or "application".
func (c *Client) ListRoles(ctx context.Context) ([]Role, *v2.RateLimitDescription, error) {
	var rolesResp RolesResponse

	rateLimit, err := c.doRequest(ctx, "GET", securityV2Path+"/role/getavailableroles", nil, &rolesResp)
	if err != nil {
		return nil, rateLimit, fmt.Errorf("baton-oracle-fccs: error listing roles: %w", err)
	}

	if err := checkAPIResponseStatus(&APIResponse{Status: rolesResp.Status, Error: rolesResp.Error}); err != nil {
		return nil, rateLimit, err
	}

	return rolesResp.Details, rateLimit, nil
}

// GetRoleUserAssignments fetches users assigned to a specific role using the V2 Report API.
// The API returns users with their roles array; we filter by the specified role name.
func (c *Client) GetRoleUserAssignments(ctx context.Context, roleName string) ([]string, *v2.RateLimitDescription, error) {
	encodedRole := url.QueryEscape(roleName)
	path := fmt.Sprintf("%s/report/roleassignmentreport/user?rolename=%s", securityV2Path, encodedRole)
	var report RoleAssignmentUserResponse

	rateLimit, err := c.doRequest(ctx, "GET", path, nil, &report)
	if err != nil {
		return nil, rateLimit, fmt.Errorf("baton-oracle-fccs: error fetching user role assignments: %w", err)
	}

	if err := checkAPIResponseStatus(&APIResponse{Status: report.Status, Error: report.Error}); err != nil {
		return nil, rateLimit, err
	}

	// The API filters by rolename, so all returned users have this role
	var users []string
	for _, detail := range report.Details {
		if detail.UserLogin != "" {
			users = append(users, detail.UserLogin)
		}
	}
	return users, rateLimit, nil
}

// GetRoleGroupAssignments fetches groups assigned to a specific role using the V2 Report API.
// The API returns groups with their roles array; we filter by the specified role name.
func (c *Client) GetRoleGroupAssignments(ctx context.Context, roleName string) ([]string, *v2.RateLimitDescription, error) {
	encodedRole := url.QueryEscape(roleName)
	path := fmt.Sprintf("%s/report/roleassignmentreport/group?rolename=%s", securityV2Path, encodedRole)
	var report RoleAssignmentGroupResponse

	rateLimit, err := c.doRequest(ctx, "GET", path, nil, &report)
	if err != nil {
		return nil, rateLimit, fmt.Errorf("baton-oracle-fccs: error fetching group role assignments: %w", err)
	}

	if err := checkAPIResponseStatus(&APIResponse{Status: report.Status, Error: report.Error}); err != nil {
		return nil, rateLimit, err
	}

	// The API filters by rolename, so all returned groups have this role
	var groups []string
	for _, detail := range report.Details {
		if detail.GroupName != "" {
			groups = append(groups, detail.GroupName)
		}
	}
	return groups, rateLimit, nil
}

// GetAllUserRoleAssignments fetches all user-role assignments in one API call.
// Returns a map of role name -> list of user logins.
// This is much more efficient than calling GetRoleUserAssignments for each role.
func (c *Client) GetAllUserRoleAssignments(ctx context.Context) (map[string][]string, *v2.RateLimitDescription, error) {
	var report RoleAssignmentUserResponse

	rateLimit, err := c.doRequest(ctx, "GET", securityV2Path+"/report/roleassignmentreport/user", nil, &report)
	if err != nil {
		return nil, rateLimit, fmt.Errorf("baton-oracle-fccs: error fetching all user role assignments: %w", err)
	}

	if err := checkAPIResponseStatus(&APIResponse{Status: report.Status, Error: report.Error}); err != nil {
		return nil, rateLimit, err
	}

	// Build map of role name -> user logins
	result := make(map[string][]string)
	for _, detail := range report.Details {
		if detail.UserLogin == "" {
			continue
		}
		for _, role := range detail.Roles {
			if role.RoleName != "" {
				result[role.RoleName] = append(result[role.RoleName], detail.UserLogin)
			}
		}
	}
	return result, rateLimit, nil
}

// GetAllGroupRoleAssignments fetches all group-role assignments in one API call.
// Returns a map of role name -> list of group names.
// This is much more efficient than calling GetRoleGroupAssignments for each role.
func (c *Client) GetAllGroupRoleAssignments(ctx context.Context) (map[string][]string, *v2.RateLimitDescription, error) {
	var report RoleAssignmentGroupResponse

	rateLimit, err := c.doRequest(ctx, "GET", securityV2Path+"/report/roleassignmentreport/group", nil, &report)
	if err != nil {
		return nil, rateLimit, fmt.Errorf("baton-oracle-fccs: error fetching all group role assignments: %w", err)
	}

	if err := checkAPIResponseStatus(&APIResponse{Status: report.Status, Error: report.Error}); err != nil {
		return nil, rateLimit, err
	}

	// Build map of role name -> group names
	result := make(map[string][]string)
	for _, detail := range report.Details {
		if detail.GroupName == "" {
			continue
		}
		for _, role := range detail.Roles {
			if role.RoleName != "" {
				result[role.RoleName] = append(result[role.RoleName], detail.GroupName)
			}
		}
	}
	return result, rateLimit, nil
}

// GetGroupMembers fetches users who are members of a specific group using the User Group Report API.
// Uses GET /interop/rest/security/v2/report/usergroupreport?groupname={groupName}
func (c *Client) GetGroupMembers(ctx context.Context, groupName string) ([]UserGroupReportDetail, *v2.RateLimitDescription, error) {
	encodedGroupName := url.QueryEscape(groupName)
	path := fmt.Sprintf("%s/report/usergroupreport?groupname=%s", securityV2Path, encodedGroupName)
	var report UserGroupReportResponse

	rateLimit, err := c.doRequest(ctx, "GET", path, nil, &report)
	if err != nil {
		return nil, rateLimit, fmt.Errorf("baton-oracle-fccs: error fetching group members: %w", err)
	}

	if err := checkAPIResponseStatus(&APIResponse{Status: report.Status, Error: report.Error}); err != nil {
		return nil, rateLimit, err
	}

	return report.Details, rateLimit, nil
}

// AssignRoleToUser assigns a role to a user.
// Uses PUT /interop/rest/security/v2/role/assign/user
// Reference: https://docs.oracle.com/en/cloud/saas/enterprise-performance-management-common/prest/lcm_assign_role_v2.html
func (c *Client) AssignRoleToUser(ctx context.Context, userLogin, roleName string) error {
	startTime := time.Now()
	c.logger.Info("assigning role to user",
		zap.String("user_login", userLogin),
		zap.String("role_name", roleName))

	reqBody := map[string]interface{}{
		"rolename": roleName,
		"users": []map[string]interface{}{
			{
				"userlogin": userLogin,
			},
		},
	}

	path := securityV2Path + "/role/assign/user"
	var apiResp APIResponse
	_, err := c.doRequest(ctx, "PUT", path, reqBody, &apiResp)
	if err != nil {
		c.logger.Error("failed to assign role to user",
			zap.Error(err),
			zap.String("user_login", userLogin),
			zap.String("role_name", roleName))
		return fmt.Errorf("baton-oracle-fccs: error assigning role to user: %w", err)
	}

	if err := c.checkAPIResponseStatusWithLogging(&apiResp, map[string]interface{}{
		"user_login": userLogin,
		"role_name":  roleName,
	}); err != nil {
		return err
	}

	duration := time.Since(startTime)
	c.logger.Info("successfully assigned role to user",
		zap.String("user_login", userLogin),
		zap.String("role_name", roleName),
		zap.Duration("duration", duration))

	return nil
}

// RemoveRoleFromUser removes a role assignment from a user.
// Uses PUT /interop/rest/security/v2/role/unassign/user
// Reference: https://docs.oracle.com/en/cloud/saas/enterprise-performance-management-common/prest/lcm_unassign_role_v2.html
func (c *Client) RemoveRoleFromUser(ctx context.Context, userLogin, roleName string) error {
	startTime := time.Now()
	c.logger.Info("removing role from user",
		zap.String("user_login", userLogin),
		zap.String("role_name", roleName))

	reqBody := map[string]interface{}{
		"rolename": roleName,
		"users": []map[string]interface{}{
			{
				"userlogin": userLogin,
			},
		},
	}

	path := securityV2Path + "/role/unassign/user"
	var apiResp APIResponse
	_, err := c.doRequest(ctx, "PUT", path, reqBody, &apiResp)
	if err != nil {
		c.logger.Error("failed to remove role from user",
			zap.Error(err),
			zap.String("user_login", userLogin),
			zap.String("role_name", roleName))
		return fmt.Errorf("baton-oracle-fccs: error removing role from user: %w", err)
	}

	if err := c.checkAPIResponseStatusWithLogging(&apiResp, map[string]interface{}{
		"user_login": userLogin,
		"role_name":  roleName,
	}); err != nil {
		return err
	}

	duration := time.Since(startTime)
	c.logger.Info("successfully removed role from user",
		zap.String("user_login", userLogin),
		zap.String("role_name", roleName),
		zap.Duration("duration", duration))

	return nil
}

// AssignRoleToGroup assigns a role to a group.
// Uses POST /interop/rest/security/v2/role/assign
func (c *Client) AssignRoleToGroup(ctx context.Context, groupName, roleName string) error {
	startTime := time.Now()
	c.logger.Info("assigning role to group",
		zap.String("group_name", groupName),
		zap.String("role_name", roleName))

	reqBody := map[string]interface{}{
		"groupname": groupName,
		"rolename":  roleName,
	}

	var apiResp APIResponse
	_, err := c.doRequest(ctx, "POST", rolesPath+"/assign", reqBody, &apiResp)
	if err != nil {
		c.logger.Error("failed to assign role to group",
			zap.Error(err),
			zap.String("group_name", groupName),
			zap.String("role_name", roleName))
		return fmt.Errorf("baton-oracle-fccs: error assigning role to group: %w", err)
	}

	if err := checkAPIResponseStatus(&apiResp); err != nil {
		return err
	}

	duration := time.Since(startTime)
	c.logger.Info("successfully assigned role to group",
		zap.String("group_name", groupName),
		zap.String("role_name", roleName),
		zap.Duration("duration", duration))

	return nil
}

// RemoveRoleFromGroup removes a role assignment from a group.
// Uses DELETE /interop/rest/security/v2/role/assign
func (c *Client) RemoveRoleFromGroup(ctx context.Context, groupName, roleName string) error {
	startTime := time.Now()
	c.logger.Info("removing role from group",
		zap.String("group_name", groupName),
		zap.String("role_name", roleName))

	reqBody := map[string]interface{}{
		"groupname": groupName,
		"rolename":  roleName,
	}

	var apiResp APIResponse
	_, err := c.doRequest(ctx, "DELETE", rolesPath+"/assign", reqBody, &apiResp)
	if err != nil {
		c.logger.Error("failed to remove role from group",
			zap.Error(err),
			zap.String("group_name", groupName),
			zap.String("role_name", roleName))
		return fmt.Errorf("baton-oracle-fccs: error removing role from group: %w", err)
	}

	if err := checkAPIResponseStatus(&apiResp); err != nil {
		return err
	}

	duration := time.Since(startTime)
	c.logger.Info("successfully removed role from group",
		zap.String("group_name", groupName),
		zap.String("role_name", roleName),
		zap.Duration("duration", duration))

	return nil
}

// verifyGroupExists verifies that a group exists by listing all groups and searching for it.
// This is more reliable than using GetGroup() with a filter, which may have matching issues.
// Returns (exists, error) where exists is true if the group was found, false otherwise.
// If a case mismatch is detected, returns an error with the actual group name.
func (c *Client) verifyGroupExists(ctx context.Context, groupName string) (bool, error) {
	// List all groups and search for the group name
	allGroups, _, err := c.ListGroups(ctx)
	if err != nil {
		return false, fmt.Errorf("baton-oracle-fccs: failed to list groups for verification: %w", err)
	}
	
	// Search for exact match (case-sensitive)
	for _, group := range allGroups {
		if group.GroupName == groupName {
			return true, nil
		}
	}
	
	// Also try case-insensitive search for better error messages
	for _, group := range allGroups {
		if strings.EqualFold(group.GroupName, groupName) {
			c.logger.Warn("group name case mismatch detected",
				zap.String("requested_name", groupName),
				zap.String("actual_name", group.GroupName))
			return false, fmt.Errorf("baton-oracle-fccs: group '%s' not found, but found similar group '%s' (case mismatch?)", groupName, group.GroupName)
		}
	}
	
	return false, nil
}

// AddUserToGroup adds a user to a group.
// Uses PUT /interop/rest/security/v2/groups/adduserstogroup
// Reference: https://docs.oracle.com/en/cloud/saas/enterprise-performance-management-common/prest/lcm_add_user_to_group_v2.html
func (c *Client) AddUserToGroup(ctx context.Context, groupName, userLogin string) error {
	startTime := time.Now()
	c.logger.Info("adding user to group",
		zap.String("user_login", userLogin),
		zap.String("group_name", groupName))

	// Check if user exists in FCCS (they may not be visible yet if no role assigned)
	// For bundled tasks, we'll retry a few times to allow role assignment to complete
	var userExists bool
	for attempt := 0; attempt < c.userExistenceRetries; attempt++ {
		if attempt > 0 {
			c.logger.Debug("retrying user existence check",
				zap.String("user_login", userLogin),
				zap.String("group_name", groupName),
				zap.Int("attempt", attempt+1),
				zap.Int("max_retries", c.userExistenceRetries))
			time.Sleep(c.userExistenceRetryDelay)
		}
		
		_, _, getUserErr := c.GetUser(ctx, userLogin)
		if getUserErr == nil {
			userExists = true
			break
		}
		
		// If it's the last attempt, we'll fail below
		if attempt < c.userExistenceRetries-1 {
			c.logger.Debug("user not found in FCCS, will retry (may be syncing from role assignment)",
				zap.Error(getUserErr),
				zap.String("user_login", userLogin),
				zap.String("group_name", groupName),
				zap.Int("attempt", attempt+1))
		}
	}

	if !userExists {
		c.logger.Error("user not found in FCCS after retries when adding to group",
			zap.String("user_login", userLogin),
			zap.String("group_name", groupName),
			zap.Int("retries", c.userExistenceRetries))
		return fmt.Errorf("baton-oracle-fccs: cannot add user %s to group %s: user does not exist in FCCS. Users must have at least one role assigned before they become visible in FCCS. Please assign a role to the user first, then retry adding them to the group", userLogin, groupName)
	}

	reqBody := map[string]interface{}{
		"groupname": groupName,
		"users": []map[string]interface{}{
			{
				"userlogin": userLogin,
			},
		},
	}

	path := securityV2Path + "/groups/adduserstogroup"
	var apiResp APIResponse
	_, err := c.doRequest(ctx, "PUT", path, reqBody, &apiResp)
	if err != nil {
		// Check if it's a 404 - group might not exist or endpoint is wrong
		if strings.Contains(err.Error(), "404") || strings.Contains(err.Error(), "not found") {
			c.logger.Warn("404 error when adding user to group, verifying group exists",
				zap.String("user_login", userLogin),
				zap.String("group_name", groupName))
			// Verify the group exists
			if verifyErr := c.handleGroupNotFoundError(ctx, groupName, fmt.Sprintf("adding user %s to group %s", userLogin, groupName)); verifyErr != nil {
				c.logger.Error("group not found when adding user",
					zap.String("user_login", userLogin),
					zap.String("group_name", groupName))
				return fmt.Errorf("baton-oracle-fccs: error adding user %s to group %s: %w", userLogin, groupName, verifyErr)
			}
			// Group exists but endpoint returned 404 - might be API version or permission issue
			c.logger.Error("group exists but API returned 404",
				zap.String("user_login", userLogin),
				zap.String("group_name", groupName),
				zap.String("endpoint", path))
			return fmt.Errorf("baton-oracle-fccs: error adding user %s to group %s: received 404 Not Found from endpoint %s. The group exists but the API call failed. This may indicate: (1) incorrect API endpoint, (2) insufficient permissions, or (3) the user '%s' does not exist", userLogin, groupName, path, userLogin)
		}
		c.logger.Error("failed to add user to group",
			zap.Error(err),
			zap.String("user_login", userLogin),
			zap.String("group_name", groupName))
		return fmt.Errorf("baton-oracle-fccs: error adding user %s to group %s: %w", userLogin, groupName, err)
	}

	// Check for API errors before general status check
	if apiResp.Status != 0 {
		if apiResp.Error != nil {
			errorCode := apiResp.Error.ErrorCode
			errorMsg := strings.ToLower(apiResp.Error.ErrorMessage)
			
			// Check if error indicates group doesn't exist
			if errorCode == "EPMCSS-21021" || strings.Contains(errorMsg, "does not exist") || strings.Contains(errorMsg, "not found") {
				// Verify if group actually exists
				if verifyErr := c.handleGroupNotFoundError(ctx, groupName, fmt.Sprintf("adding user %s to group %s", userLogin, groupName)); verifyErr != nil {
					c.logger.Error("group not found when adding user",
						zap.String("user_login", userLogin),
						zap.String("group_name", groupName),
						zap.String("api_error_code", errorCode),
						zap.String("api_error_message", apiResp.Error.ErrorMessage))
					return fmt.Errorf("baton-oracle-fccs: error adding user %s to group %s: %w", userLogin, groupName, verifyErr)
				}
				
				// Group exists but API says it doesn't - this is unexpected
				c.logger.Error("group exists but API returned 'does not exist' error",
					zap.String("user_login", userLogin),
					zap.String("group_name", groupName),
					zap.String("api_error_code", errorCode),
					zap.String("api_error_message", apiResp.Error.ErrorMessage))
				return fmt.Errorf("baton-oracle-fccs: API error %s: %s (group exists but API returned error)", errorCode, apiResp.Error.ErrorMessage)
			}
		}
		
		// Other API errors - log and return
		if err := c.checkAPIResponseStatusWithLogging(&apiResp, map[string]interface{}{
			"user_login": userLogin,
			"group_name": groupName,
		}); err != nil {
			return err
		}
	}

	duration := time.Since(startTime)
	c.logger.Info("successfully added user to group",
		zap.String("user_login", userLogin),
		zap.String("group_name", groupName),
		zap.Duration("duration", duration))

	return nil
}

// RemoveUserFromGroup removes a user from a group.
// Uses PUT /interop/rest/security/v2/groups/removeusersfromgroup
// Reference: https://docs.oracle.com/en/cloud/saas/enterprise-performance-management-common/prest/lcm_remove_user_from_group_v2.html
// This operation is idempotent - if the user is not a member, it returns success.
func (c *Client) RemoveUserFromGroup(ctx context.Context, groupName, userLogin string) error {
	startTime := time.Now()
	c.logger.Info("removing user from group",
		zap.String("user_login", userLogin),
		zap.String("group_name", groupName))

	reqBody := map[string]interface{}{
		"groupname": groupName,
		"users": []map[string]interface{}{
			{
				"userlogin": userLogin,
			},
		},
	}

	path := securityV2Path + "/groups/removeusersfromgroup"
	var apiResp APIResponse
	_, err := c.doRequest(ctx, "PUT", path, reqBody, &apiResp)
	if err != nil {
		c.logger.Error("failed to remove user from group",
			zap.Error(err),
			zap.String("user_login", userLogin),
			zap.String("group_name", groupName))
		return fmt.Errorf("baton-oracle-fccs: error removing user from group: %w", err)
	}

	// Check for API errors
	if apiResp.Status != 0 {
		if apiResp.Error != nil {
			errorCode := apiResp.Error.ErrorCode
			errorMsg := strings.ToLower(apiResp.Error.ErrorMessage)
			
			// Check if error indicates group doesn't exist
			if strings.Contains(errorMsg, "does not exist") || strings.Contains(errorMsg, "not found") {
				// Verify if group actually exists
				if verifyErr := c.handleGroupNotFoundError(ctx, groupName, fmt.Sprintf("removing user %s from group %s", userLogin, groupName)); verifyErr != nil {
					c.logger.Error("group not found when removing user",
						zap.String("user_login", userLogin),
						zap.String("group_name", groupName),
						zap.String("api_error_code", errorCode),
						zap.String("api_error_message", apiResp.Error.ErrorMessage))
					return fmt.Errorf("baton-oracle-fccs: error removing user %s from group %s: %w", userLogin, groupName, verifyErr)
				}
				
				// Group exists - check if user is actually a member
				// If user is not a member, treat as success (idempotent operation)
				members, _, membersErr := c.GetGroupMembers(ctx, groupName)
				if membersErr != nil {
					// Can't verify membership, return original error
					c.logger.Warn("group exists but cannot verify user membership",
						zap.Error(membersErr),
						zap.String("user_login", userLogin),
						zap.String("group_name", groupName))
					return fmt.Errorf("baton-oracle-fccs: API error %s: %s", errorCode, apiResp.Error.ErrorMessage)
				}
				
				// Check if user is in the members list
				userIsMember := false
				for _, member := range members {
					if member.UserLogin == userLogin {
						userIsMember = true
						break
					}
				}
				
				if !userIsMember {
					// User is not a member - this is idempotent, treat as success
					c.logger.Info("user is not a member of group, treating removal as success (idempotent)",
						zap.String("user_login", userLogin),
						zap.String("group_name", groupName))
					duration := time.Since(startTime)
					c.logger.Info("successfully removed user from group (user was not a member)",
						zap.String("user_login", userLogin),
						zap.String("group_name", groupName),
						zap.Duration("duration", duration))
					return nil
				}
				
				// User is a member but API says group doesn't exist - this is unexpected
				c.logger.Error("group exists and user is a member, but API returned error",
					zap.String("user_login", userLogin),
					zap.String("group_name", groupName),
					zap.String("api_error_code", errorCode),
					zap.String("api_error_message", apiResp.Error.ErrorMessage))
				return fmt.Errorf("baton-oracle-fccs: API error %s: %s (group exists and user is a member, but removal failed)", errorCode, apiResp.Error.ErrorMessage)
			}
		}
		
		// Other API errors - log and return
		if err := c.checkAPIResponseStatusWithLogging(&apiResp, map[string]interface{}{
			"user_login": userLogin,
			"group_name": groupName,
		}); err != nil {
			return err
		}
	}

	duration := time.Since(startTime)
	c.logger.Info("successfully removed user from group",
		zap.String("user_login", userLogin),
		zap.String("group_name", groupName),
		zap.Duration("duration", duration))

	return nil
}

// AddGroupToGroup adds a group to another group (nested group membership).
// Note: The v2 API (adduserstogroup) is specifically for users, not groups.
// Nested group membership may still require the v1 API.
// Uses POST /interop/rest/security/v1/groups/{groupname}/members
func (c *Client) AddGroupToGroup(ctx context.Context, parentGroupName, childGroupName string) error {
	startTime := time.Now()
	c.logger.Info("adding group to group",
		zap.String("parent_group", parentGroupName),
		zap.String("child_group", childGroupName))

	reqBody := map[string]interface{}{
		"groupname": childGroupName,
	}

	path := fmt.Sprintf("%s/%s/members", groupsPath, url.QueryEscape(parentGroupName))
	var apiResp APIResponse
	_, err := c.doRequest(ctx, "POST", path, reqBody, &apiResp)
	if err != nil {
		c.logger.Error("failed to add group to group",
			zap.Error(err),
			zap.String("parent_group", parentGroupName),
			zap.String("child_group", childGroupName))
		return fmt.Errorf("baton-oracle-fccs: error adding group to group: %w", err)
	}

	if err := checkAPIResponseStatus(&apiResp); err != nil {
		return err
	}

	duration := time.Since(startTime)
	c.logger.Info("successfully added group to group",
		zap.String("parent_group", parentGroupName),
		zap.String("child_group", childGroupName),
		zap.Duration("duration", duration))

	return nil
}

// RemoveGroupFromGroup removes a group from another group (nested group membership).
// Uses DELETE /interop/rest/security/v1/groups/{groupname}/members/{groupname}
func (c *Client) RemoveGroupFromGroup(ctx context.Context, parentGroupName, childGroupName string) error {
	startTime := time.Now()
	c.logger.Info("removing group from group",
		zap.String("parent_group", parentGroupName),
		zap.String("child_group", childGroupName))

	path := fmt.Sprintf("%s/%s/members/%s", groupsPath, url.QueryEscape(parentGroupName), url.QueryEscape(childGroupName))
	var apiResp APIResponse
	_, err := c.doRequest(ctx, "DELETE", path, nil, &apiResp)
	if err != nil {
		c.logger.Error("failed to remove group from group",
			zap.Error(err),
			zap.String("parent_group", parentGroupName),
			zap.String("child_group", childGroupName))
		return fmt.Errorf("baton-oracle-fccs: error removing group from group: %w", err)
	}

	if err := checkAPIResponseStatus(&apiResp); err != nil {
		return err
	}

	duration := time.Since(startTime)
	c.logger.Info("successfully removed group from group",
		zap.String("parent_group", parentGroupName),
		zap.String("child_group", childGroupName),
		zap.Duration("duration", duration))

	return nil
}
