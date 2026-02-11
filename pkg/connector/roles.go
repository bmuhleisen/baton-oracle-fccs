package connector

import (
	"context"
	"fmt"
	"time"

	"github.com/conductorone/baton-oracle-fccs/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	grantSdk "github.com/conductorone/baton-sdk/pkg/types/grant"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// roleResourceType syncs role resources from Oracle FCCS.
type roleResourceType struct {
	client *client.Client
	// Cache role assignments to avoid 2*N API calls
	// Maps role name -> list of user logins
	userAssignmentsCache map[string][]string
	// Maps role name -> list of group names
	groupAssignmentsCache map[string][]string
	// Track if cache has been populated
	cachePopulated bool
}

// roleBuilder creates a new role resource syncer.
func roleBuilder(c *client.Client) *roleResourceType {
	return &roleResourceType{
		client:                c,
		userAssignmentsCache:  make(map[string][]string),
		groupAssignmentsCache: make(map[string][]string),
	}
}

// ResourceType returns the resource type for roles.
func (r *roleResourceType) ResourceType(ctx context.Context) *v2.ResourceType {
	return resourceTypeRole
}

// List returns all roles from Oracle FCCS.
// Uses GET /interop/rest/security/v2/role/getavailableroles
func (r *roleResourceType) List(ctx context.Context, parentResourceID *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	startTime := time.Now()
	l := ctxzap.Extract(ctx)
	l.Info("listing roles", zap.Time("start_time", startTime))

	// Check if we've already fetched all roles (no pagination support)
	if opts.PageToken.Token != "" {
		return nil, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, nil
	}

	roles, rateLimit, err := r.client.ListRoles(ctx)
	if err != nil {
		l.Error("failed to list roles", zap.Error(err))
		return nil, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, fmt.Errorf("baton-oracle-fccs: failed to list roles: %w", err)
	}

	var resources []*v2.Resource
	var errors []error
	for _, role := range roles {
		// Check for context cancellation to allow early termination
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		roleCopy := role
		roleResource, err := r.roleToResource(ctx, &roleCopy)
		if err != nil {
			l.Warn("failed to convert role to resource, skipping",
				zap.Error(err),
				zap.String("role_name", role.Name))
			errors = append(errors, fmt.Errorf("baton-oracle-fccs: role %s: %w", role.Name, err))
			continue // Continue processing other roles instead of failing entire sync
		}
		resources = append(resources, roleResource)
	}
	
	if len(errors) > 0 {
		l.Warn("some roles failed to convert",
			zap.Int("failed_count", len(errors)),
			zap.Int("success_count", len(resources)))
	}

	duration := time.Since(startTime)
	l.Info("successfully listed roles", 
		zap.Int("count", len(resources)),
		zap.Duration("duration", duration),
		zap.Int("errors", len(errors)))
	
	var annos annotations.Annotations
	if rateLimit != nil {
		annos.WithRateLimiting(rateLimit)
	}
	return resources, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: annos}, nil
}

// Entitlements returns the entitlements for a role.
func (r *roleResourceType) Entitlements(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	memberEntitlement := entitlementSdk.NewAssignmentEntitlement(
		resource,
		"member",
		entitlementSdk.WithGrantableTo(
			resourceTypeUser,
			resourceTypeGroup, // Support grants to groups (common in OCI)
		),
		entitlementSdk.WithDisplayName("Member"),
		entitlementSdk.WithDescription("Assignment to the role"),
	)

	return []*v2.Entitlement{memberEntitlement}, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, nil
}

// populateAssignmentsCache fetches all role assignments in 2 API calls
// and caches them for efficient lookup in Grants().
func (r *roleResourceType) populateAssignmentsCache(ctx context.Context) error {
	if r.cachePopulated {
		return nil
	}

	l := ctxzap.Extract(ctx)

	// Fetch all user-role assignments in one call
	userAssignments, _, err := r.client.GetAllUserRoleAssignments(ctx)
	if err != nil {
		l.Warn("failed to fetch all user role assignments", zap.Error(err))
		// Don't fail - just won't have user grants
	} else {
		r.userAssignmentsCache = userAssignments
	}

	// Fetch all group-role assignments in one call
	groupAssignments, _, err := r.client.GetAllGroupRoleAssignments(ctx)
	if err != nil {
		l.Warn("failed to fetch all group role assignments", zap.Error(err))
		// Don't fail - just won't have group grants
	} else {
		r.groupAssignmentsCache = groupAssignments
	}

	r.cachePopulated = true
	l.Info("role assignments cached",
		zap.Int("user_roles", len(r.userAssignmentsCache)),
		zap.Int("group_roles", len(r.groupAssignmentsCache)))
	return nil
}

// Grants returns the grants for a role using cached assignment data.
// All role assignments are fetched in 2 API calls total (not 2*N).
func (r *roleResourceType) Grants(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	// Ensure cache is populated (only makes API calls once)
	if err := r.populateAssignmentsCache(ctx); err != nil {
		return nil, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, err
	}

	// The resource ID is the role name (used directly for API calls)
	roleName := resource.Id.Resource

	l := ctxzap.Extract(ctx)
	l.Debug("fetching grants for role from cache",
		zap.String("role_name", roleName))

	var grants []*v2.Grant

	// 1. Get User Assignments from cache
	if users, ok := r.userAssignmentsCache[roleName]; ok {
		for _, userLogin := range users {
			principalID := &v2.ResourceId{
				ResourceType: resourceTypeUser.Id,
				Resource:     userLogin,
			}
			grant := grantSdk.NewGrant(resource, "member", principalID)
			grants = append(grants, grant)
		}
	}

	// 2. Get Group Assignments from cache
	if groups, ok := r.groupAssignmentsCache[roleName]; ok {
		for _, groupName := range groups {
			principalID := &v2.ResourceId{
				ResourceType: resourceTypeGroup.Id,
				Resource:     groupName,
			}
			
			// Create a minimal resource for the group to compute its member entitlement ID
			groupResource := &v2.Resource{
				Id: principalID,
			}
			groupMemberEntitlementID := entitlementSdk.NewEntitlementID(groupResource, "member")
			
			// Add GrantExpandable annotation to enable expansion: Group:member -> Role:member
			// This allows users in the group to inherit the role assignment
			expandableAnno := v2.GrantExpandable_builder{
				EntitlementIds:  []string{groupMemberEntitlementID},
				Shallow:         false, // Allow transitive expansion through nested groups
				ResourceTypeIds: []string{resourceTypeUser.Id},
			}.Build()
			
			grant := grantSdk.NewGrant(resource, "member", principalID, grantSdk.WithAnnotation(expandableAnno))
			grants = append(grants, grant)
		}
	}

	l.Debug("successfully fetched grants for role",
		zap.String("role_name", roleName),
		zap.Int("grant_count", len(grants)))
	return grants, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, nil
}

func (r *roleResourceType) roleToResource(ctx context.Context, role *client.Role) (*v2.Resource, error) {
	// The Oracle EPM API returns roles with "name" (display name)
	// We use the role name as the resource ID since API calls require role names
	profile := map[string]interface{}{
		"role_name": role.Name,
	}

	roleTraitOptions := []resourceSdk.RoleTraitOption{
		resourceSdk.WithRoleProfile(profile),
	}

	// Use the role name as the resource ID since API calls require role names
	resourceType := r.ResourceType(ctx)
	resource, err := resourceSdk.NewRoleResource(
		role.Name, // Display name (human-readable)
		resourceType,
		role.Name, // Resource ID - use role name directly
		roleTraitOptions,
	)
	if err != nil {
		return nil, fmt.Errorf("baton-oracle-fccs: failed to create role resource: %w", err)
	}

	return resource, nil
}

// Grant assigns a role to a principal (user or group).
// Implements GrantProvisionerV2 for ResourceProvisionerV2.
// resource is the principal (user or group), entitlement contains the role resource.
func (r *roleResourceType) Grant(ctx context.Context, resource *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	startTime := time.Now()
	
	// The resource parameter is the principal (user or group receiving the role)
	principalID := resource.Id
	principalType := principalID.ResourceType
	principalResourceID := principalID.Resource
	
	// The entitlement contains the role resource
	roleResource := entitlement.GetResource()
	if roleResource == nil {
		return nil, nil, fmt.Errorf("baton-oracle-fccs: entitlement must have a resource (role)")
	}
	
	// The resource ID is the role name (used directly for API calls)
	roleName := roleResource.Id.Resource
	
	l := ctxzap.Extract(ctx)
	l.Info("granting role",
		zap.String("role_name", roleName),
		zap.String("principal_type", principalType),
		zap.String("principal_id", principalResourceID),
		zap.Time("start_time", startTime))
	
	var err error
	switch principalType {
	case "user":
		err = r.client.AssignRoleToUser(ctx, principalResourceID, roleName)
	case "group":
		err = r.client.AssignRoleToGroup(ctx, principalResourceID, roleName)
	default:
		return nil, nil, fmt.Errorf("baton-oracle-fccs: unsupported principal type for role assignment: %s", principalType)
	}
	
	if err != nil {
		l.Error("failed to grant role",
			zap.Error(err),
			zap.String("role_name", roleName),
			zap.String("principal_type", principalType),
			zap.String("principal_id", principalResourceID))
		return nil, nil, fmt.Errorf("baton-oracle-fccs: failed to grant role %s to %s %s: %w", roleName, principalType, principalResourceID, err)
	}
	
	duration := time.Since(startTime)
	l.Info("successfully granted role",
		zap.String("role_name", roleName),
		zap.String("principal_type", principalType),
		zap.String("principal_id", principalResourceID),
		zap.Duration("duration", duration))
	
	// Create and return the grant
	grant := grantSdk.NewGrant(
		roleResource,
		entitlement.Id,
		resource.Id,
	)
	
	return []*v2.Grant{grant}, nil, nil
}

// Revoke removes a role assignment from a principal.
// Implements RevokeProvisioner for ResourceProvisionerV2.
func (r *roleResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	startTime := time.Now()
	
	roleResource := grant.Entitlement.Resource
	
	// The resource ID is the role name (used directly for API calls)
	roleName := roleResource.Id.Resource
	
	principal := grant.Principal
	if principal == nil {
		return nil, fmt.Errorf("baton-oracle-fccs: grant must have a principal")
	}
	principalType := principal.Id.ResourceType
	principalResourceID := principal.Id.Resource
	
	l := ctxzap.Extract(ctx)
	l.Info("revoking role",
		zap.String("role_name", roleName),
		zap.String("principal_type", principalType),
		zap.String("principal_id", principalResourceID),
		zap.Time("start_time", startTime))
	
	var err error
	switch principalType {
	case "user":
		err = r.client.RemoveRoleFromUser(ctx, principalResourceID, roleName)
	case "group":
		err = r.client.RemoveRoleFromGroup(ctx, principalResourceID, roleName)
	default:
		return nil, fmt.Errorf("baton-oracle-fccs: unsupported principal type for role revocation: %s", principalType)
	}
	
	if err != nil {
		l.Error("failed to revoke role",
			zap.Error(err),
			zap.String("role_name", roleName),
			zap.String("principal_type", principalType),
			zap.String("principal_id", principalResourceID))
		return nil, fmt.Errorf("baton-oracle-fccs: failed to revoke role %s from %s %s: %w", roleName, principalType, principalResourceID, err)
	}
	
	duration := time.Since(startTime)
	l.Info("successfully revoked role",
		zap.String("role_name", roleName),
		zap.String("principal_type", principalType),
		zap.String("principal_id", principalResourceID),
		zap.Duration("duration", duration))
	
	return nil, nil
}
