package client

// User represents an Oracle FCCS user from the REST API.
// Note: The Oracle EPM API uses lowercase field names without camelCase.
type User struct {
	UserLogin string `json:"userlogin"`
	FirstName string `json:"firstname"`
	LastName  string `json:"lastname"`
	Email     string `json:"email"`
	// MemberOf contains group memberships when requested with memberof=true
	MemberOf *UserMemberOf `json:"memberof,omitempty"`
	// Roles contains role assignments when requested with roles=true
	Roles []UserRole `json:"roles,omitempty"`
}

// UserMemberOf represents the group membership structure in user responses.
// The API can return groups as either strings or objects, so we use a flexible type.
type UserMemberOf struct {
	Groups interface{} `json:"groups,omitempty"` // Can be []string or []UserGroupMember or other structure
}

// UserRole represents a role assignment in user responses.
type UserRole struct {
	RoleName string `json:"rolename"`
	ID       string `json:"id,omitempty"`
}

// GroupMember represents a member of a group (can be a user or another group).
type GroupMember struct {
	UserLogin string `json:"userlogin,omitempty"`
	GroupName string `json:"groupname,omitempty"`
}

// GroupMembers container for the V2 API structure.
type GroupMembers struct {
	Users  []GroupMember `json:"users,omitempty"`
	Groups []GroupMember `json:"groups,omitempty"`
}

// Group represents an Oracle FCCS group from the role assignment report.
type Group struct {
	GroupName   string       `json:"groupname"`
	Description string       `json:"description,omitempty"`
	Type        string       `json:"type,omitempty"` // "IDCS" or "EPM"
	Members     GroupMembers `json:"members,omitempty"`
	// Roles from the role assignment report
	Roles []GroupRole `json:"roles,omitempty"`
}

// GroupRole represents a role assignment for a group.
type GroupRole struct {
	RoleName            string `json:"rolename"`
	RoleType            string `json:"roletype,omitempty"` // "Predefined" or "Application"
	GrantedThroughGroup string `json:"grantedthroughgroup,omitempty"`
}

// Role represents an Oracle FCCS role definition from getavailableroles.
// Note: The API returns "name" and "id", not "roleName".
type Role struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// RoleAssignmentUserDetail represents a user in the role assignment report.
type RoleAssignmentUserDetail struct {
	UserLogin string     `json:"userlogin"`
	FirstName string     `json:"firstname"`
	LastName  string     `json:"lastname"`
	Email     string     `json:"email"`
	Roles     []RoleInfo `json:"roles,omitempty"`
}

// RoleAssignmentGroupDetail represents a group in the role assignment report.
type RoleAssignmentGroupDetail struct {
	GroupName   string     `json:"groupname"`
	Description string     `json:"description,omitempty"`
	Type        string     `json:"type,omitempty"` // "IDCS" or "EPM"
	Roles       []RoleInfo `json:"roles,omitempty"`
}

// RoleInfo represents role information in assignment reports.
type RoleInfo struct {
	RoleName            string `json:"rolename"`
	RoleType            string `json:"roletype,omitempty"`
	GrantedThroughGroup string `json:"grantedthroughgroup,omitempty"`
}

// Link represents a HATEOAS link.
type Link struct {
	Href   string `json:"href"`
	Action string `json:"action,omitempty"`
	Rel    string `json:"rel,omitempty"`
}

// APIResponse represents the standard Oracle EPM API response structure.
// v2 APIs include additional Details field with processing results.
type APIResponse struct {
	Links   interface{}      `json:"links,omitempty"`
	Status  int              `json:"status"`
	Error   *APIError        `json:"error,omitempty"`
	Details *APIResponseDetails `json:"details,omitempty"` // v2 API details
}

// APIResponseDetails represents the details field in v2 API responses.
// Used by batch operations like add users, add users to group, etc.
type APIResponseDetails struct {
	Processed   int                `json:"processed"`
	Succeeded   int                `json:"succeeded"`
	Failed      int                `json:"failed"`
	FailedItems []APIResponseFailedItem `json:"faileditems,omitempty"`
}

// APIResponseFailedItem represents a failed item in batch operation responses.
type APIResponseFailedItem struct {
	UserLogin    string `json:"userlogin,omitempty"`
	GroupName   string `json:"groupname,omitempty"`
	ErrorCode   string `json:"errorcode"`
	ErrorMessage string `json:"errormessage"`
}

// APIError represents an error in the Oracle EPM API response.
type APIError struct {
	ErrorCode    string `json:"errorcode"`
	ErrorMessage string `json:"errormessage"`
}

// UsersResponse represents the response from the users list API (v1).
// Uses POST /interop/rest/security/v1/users/list
type UsersResponse struct {
	Links   interface{} `json:"links,omitempty"`
	Status  int         `json:"status"`
	Error   *APIError   `json:"error,omitempty"`
	Details []User      `json:"details"`
}

// UsersListRequest represents the request body for listing users.
type UsersListRequest struct {
	UserLogin     string `json:"userlogin,omitempty"`
	MemberOf      bool   `json:"memberof,omitempty"`
	Roles         bool   `json:"roles,omitempty"`
	UserAttribute string `json:"userattribute,omitempty"`
}

// GroupsResponse represents the response from the groups list API (v1).
// Uses POST /interop/rest/security/v1/groups/list
type GroupsResponse struct {
	Links   interface{}   `json:"links,omitempty"`
	Status  int           `json:"status"`
	Error   *APIError     `json:"error,omitempty"`
	Details []GroupDetail `json:"details"`
}

// GroupsListRequest represents the request body for listing groups.
type GroupsListRequest struct {
	GroupName string   `json:"groupname,omitempty"`
	Type      []string `json:"type,omitempty"`    // "EPM", "IDCS", "PREDEFINED"
	Members   bool     `json:"members,omitempty"` // Include user/group members
	Roles     bool     `json:"roles,omitempty"`   // Include assigned roles
}

// GroupDetail represents a group from the list groups API.
type GroupDetail struct {
	GroupName   string        `json:"groupname"`
	Description string        `json:"description,omitempty"`
	Type        string        `json:"type,omitempty"`     // "IDCS", "EPM", "PREDEFINED"
	Identity    string        `json:"identity,omitempty"` // Group identity
	Members     *GroupMembers `json:"members,omitempty"`  // User and group members
	Roles       []RoleInfo    `json:"roles,omitempty"`    // Assigned roles
}

// RolesResponse represents the response from the getavailableroles API.
// Uses GET /interop/rest/security/v2/role/getavailableroles
type RolesResponse struct {
	Links   interface{} `json:"links,omitempty"`
	Status  int         `json:"status"`
	Error   *APIError   `json:"error,omitempty"`
	Details []Role      `json:"details"`
}

// RoleAssignmentUserResponse represents the response from roleassignmentreport/user.
type RoleAssignmentUserResponse struct {
	Links   interface{}                `json:"links,omitempty"`
	Status  int                        `json:"status"`
	Error   *APIError                  `json:"error,omitempty"`
	Details []RoleAssignmentUserDetail `json:"details"`
}

// RoleAssignmentGroupResponse represents the response from roleassignmentreport/group.
type RoleAssignmentGroupResponse struct {
	Links   interface{}                 `json:"links,omitempty"`
	Status  int                         `json:"status"`
	Error   *APIError                   `json:"error,omitempty"`
	Details []RoleAssignmentGroupDetail `json:"details"`
}

// UserGroupReportDetail represents a user in the user group report.
// Uses GET /interop/rest/security/v2/report/usergroupreport
type UserGroupReportDetail struct {
	UserLogin string            `json:"userlogin"`
	FirstName string            `json:"firstname"`
	LastName  string            `json:"lastname"`
	Email     string            `json:"email"`
	Groups    []UserGroupMember `json:"groups,omitempty"`
}

// UserGroupMember represents a group membership in the user group report.
type UserGroupMember struct {
	GroupName string `json:"groupname"`
	Direct    string `json:"direct"` // "Yes" or "No"
}

// UserGroupReportResponse represents the response from usergroupreport API.
type UserGroupReportResponse struct {
	Links   interface{}             `json:"links,omitempty"`
	Status  int                     `json:"status"`
	Error   *APIError               `json:"error,omitempty"`
	Details []UserGroupReportDetail `json:"details"`
}

// OAuthTokenResponse represents the OAuth2 token response.
type OAuthTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}
