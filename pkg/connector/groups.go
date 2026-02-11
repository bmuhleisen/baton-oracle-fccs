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

// groupResourceType syncs group resources from Oracle FCCS.
type groupResourceType struct {
	client *client.Client
	// Cache groups data from List() to avoid redundant API calls in Grants()
	groupsCache map[string]*client.GroupDetail
}

// groupBuilder creates a new group resource syncer.
func groupBuilder(c *client.Client) *groupResourceType {
	return &groupResourceType{
		client:      c,
		groupsCache: make(map[string]*client.GroupDetail),
	}
}

// ResourceType returns the resource type for groups.
func (g *groupResourceType) ResourceType(ctx context.Context) *v2.ResourceType {
	return resourceTypeGroup
}

// List returns all groups from Oracle FCCS.
// Groups are cached with members to avoid redundant API calls in Grants().
func (g *groupResourceType) List(ctx context.Context, parentResourceID *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	startTime := time.Now()
	l := ctxzap.Extract(ctx)
	l.Info("listing groups", zap.Time("start_time", startTime))

	// Check if we've already fetched all groups (no pagination support)
	if opts.PageToken.Token != "" {
		return nil, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, nil
	}

	groups, rateLimit, err := g.client.ListGroups(ctx)
	if err != nil {
		l.Error("failed to list groups", zap.Error(err))
		return nil, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, fmt.Errorf("baton-oracle-fccs: failed to list groups: %w", err)
	}

	var resources []*v2.Resource
	var errors []error
	var excludedCount int
	for _, group := range groups {
		// Check for context cancellation to allow early termination
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		groupCopy := group
		
		// Exclude PREDEFINED type groups - these are actually Oracle Cloud roles that appear as groups
		// Oracle's API doesn't allow group operations on predefined roles, and they should be managed as roles instead
		// Reference: Oracle documentation indicates predefined IDCS roles (Service Administrator, Power User, etc.)
		// appear as groups in FCCS but are not actual groups and cannot be used in group operations
		if group.Type == "PREDEFINED" {
			l.Debug("excluding predefined role that appears as group",
				zap.String("group_name", group.GroupName),
				zap.String("type", group.Type))
			excludedCount++
			continue
		}
		
		// Cache the group data for use in Grants() - avoids N additional API calls
		// Only cache actual groups (not predefined roles)
		g.groupsCache[group.GroupName] = &groupCopy

		groupResource, err := g.groupToResource(ctx, &groupCopy)
		if err != nil {
			l.Warn("failed to convert group to resource, skipping",
				zap.Error(err),
				zap.String("group_name", group.GroupName))
			errors = append(errors, fmt.Errorf("baton-oracle-fccs: group %s: %w", group.GroupName, err))
			continue // Continue processing other groups instead of failing entire sync
		}
		resources = append(resources, groupResource)
	}
	
	if excludedCount > 0 {
		l.Info("excluded predefined roles that appear as groups",
			zap.Int("excluded_count", excludedCount),
			zap.String("note", "These are Oracle Cloud roles, not groups, and should be managed via role assignments"))
	}
	
	if len(errors) > 0 {
		l.Warn("some groups failed to convert",
			zap.Int("failed_count", len(errors)),
			zap.Int("success_count", len(resources)))
	}

	duration := time.Since(startTime)
	l.Info("successfully listed groups", 
		zap.Int("count", len(resources)),
		zap.Duration("duration", duration),
		zap.Int("errors", len(errors)))
	
	var annos annotations.Annotations
	if rateLimit != nil {
		annos.WithRateLimiting(rateLimit)
	}
	return resources, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: annos}, nil
}

// Entitlements returns the entitlements for a group.
func (g *groupResourceType) Entitlements(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	// Group membership entitlement - can be granted to users and nested groups
	memberEntitlement := entitlementSdk.NewAssignmentEntitlement(
		resource,
		"member",
		entitlementSdk.WithGrantableTo(
			resourceTypeUser,
			resourceTypeGroup, // Support nested group membership
		),
		entitlementSdk.WithDisplayName("Member"),
		entitlementSdk.WithDescription("Membership in the group"),
	)

	return []*v2.Entitlement{memberEntitlement}, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, nil
}

// Grants returns the grants for a group.
// Uses cached group data from List() to avoid redundant API calls.
func (g *groupResourceType) Grants(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	groupName := resource.Id.Resource
	l := ctxzap.Extract(ctx)
	l.Debug("fetching grants for group", zap.String("group_name", groupName))

	// Try to get group from cache first (populated during List())
	group, ok := g.groupsCache[groupName]
	if !ok {
		// Fallback to API call if not in cache (shouldn't happen in normal flow)
		l.Debug("group not in cache, fetching from API", zap.String("group_name", groupName))
		var err error
		group, _, err = g.client.GetGroup(ctx, groupName)
		if err != nil {
			l.Error("failed to get group",
				zap.Error(err),
				zap.String("group_name", groupName))
			return nil, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, fmt.Errorf("baton-oracle-fccs: failed to get group: %w", err)
		}
	}

	var grants []*v2.Grant

	// Create grants for user members
	if group.Members != nil {
		for _, userMember := range group.Members.Users {
			if userMember.UserLogin == "" {
				continue
			}
			principalID := &v2.ResourceId{
				ResourceType: resourceTypeUser.Id,
				Resource:     userMember.UserLogin,
			}
			grant := grantSdk.NewGrant(resource, "member", principalID)
			grants = append(grants, grant)
		}

		// Create grants for nested group members
		for _, groupMember := range group.Members.Groups {
			if groupMember.GroupName == "" {
				continue
			}
			principalID := &v2.ResourceId{
				ResourceType: resourceTypeGroup.Id,
				Resource:     groupMember.GroupName,
			}
			
			// Create a minimal resource for the child group to compute its member entitlement ID
			childGroupResource := &v2.Resource{
				Id: principalID,
			}
			childGroupMemberEntitlementID := entitlementSdk.NewEntitlementID(childGroupResource, "member")
			
			// Add GrantExpandable annotation to enable expansion: GroupChild:member -> GroupParent:member
			// This allows users in the child group to inherit membership in the parent group
			expandableAnno := v2.GrantExpandable_builder{
				EntitlementIds:  []string{childGroupMemberEntitlementID},
				Shallow:         false, // Allow transitive expansion through nested groups
				ResourceTypeIds: []string{resourceTypeUser.Id},
			}.Build()
			
			grant := grantSdk.NewGrant(resource, "member", principalID, grantSdk.WithAnnotation(expandableAnno))
			grants = append(grants, grant)
		}
	}

	l.Debug("successfully fetched grants for group",
		zap.String("group_name", groupName),
		zap.Int("grant_count", len(grants)))
	return grants, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, nil
}

func (g *groupResourceType) groupToResource(ctx context.Context, group *client.GroupDetail) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"group_name":  group.GroupName,
		"description": group.Description,
		"type":        group.Type, // "IDCS", "EPM", or "PREDEFINED"
	}

	if group.Identity != "" {
		profile["identity"] = group.Identity
	}

	// Add role information if available
	if len(group.Roles) > 0 {
		roleNames := make([]interface{}, 0, len(group.Roles))
		for _, role := range group.Roles {
			roleNames = append(roleNames, role.RoleName)
		}
		profile["roles"] = roleNames
	}

	groupTraitOptions := []resourceSdk.GroupTraitOption{
		resourceSdk.WithGroupProfile(profile),
	}

	resourceType := g.ResourceType(ctx)
	resource, err := resourceSdk.NewGroupResource(
		group.GroupName,
		resourceType,
		group.GroupName,
		groupTraitOptions,
	)
	if err != nil {
		return nil, fmt.Errorf("baton-oracle-fccs: failed to create group resource: %w", err)
	}

	return resource, nil
}

// validateGroupResourceType validates that the entitlement's resource is actually a group.
func validateGroupResourceType(groupResource *v2.Resource, operation string) error {
	if groupResource == nil {
		return fmt.Errorf("baton-oracle-fccs: entitlement must have a resource (group)")
	}
	
	if groupResource.Id.ResourceType != "group" {
		return fmt.Errorf("baton-oracle-fccs: invalid resource type for group membership %s: entitlement's resource should be 'group', got '%s' (resource: %s). This may indicate that '%s' exists as both a user and a group in Oracle FCCS, or the entitlement was incorrectly associated with the wrong resource type", operation, groupResource.Id.ResourceType, groupResource.Id.Resource, groupResource.Id.Resource)
	}
	
	return nil
}

// getGroupFromCacheOrAPI retrieves a group from cache or fetches it from the API.
// Returns the group name, type, and any error encountered.
func (g *groupResourceType) getGroupFromCacheOrAPI(ctx context.Context, groupNameFromResource, operation string) (groupName, groupType string, err error) {
	l := ctxzap.Extract(ctx)
	
	if cachedGroup, ok := g.groupsCache[groupNameFromResource]; ok {
		groupName = cachedGroup.GroupName
		groupType = cachedGroup.Type
		l.Debug("using group from cache",
			zap.String("operation", operation),
			zap.String("resource_id", groupNameFromResource),
			zap.String("actual_group_name", groupName),
			zap.String("group_type", groupType))
		return groupName, groupType, nil
	}
	
	// Fallback: fetch from API if not in cache
	l.Debug("group not in cache, fetching from API",
		zap.String("operation", operation),
		zap.String("group_name", groupNameFromResource))
	
	fetchedGroup, _, err := g.client.GetGroup(ctx, groupNameFromResource)
	if err != nil {
		l.Warn("failed to fetch group from API, using resource ID as group name",
			zap.Error(err),
			zap.String("operation", operation),
			zap.String("resource_id", groupNameFromResource))
		return groupNameFromResource, "", nil // Return resource ID as fallback
	}
	
	groupName = fetchedGroup.GroupName
	groupType = fetchedGroup.Type
	// Cache it for future use
	g.groupsCache[groupName] = fetchedGroup
	l.Debug("fetched group from API and cached",
		zap.String("operation", operation),
		zap.String("resource_id", groupNameFromResource),
		zap.String("actual_group_name", groupName),
		zap.String("group_type", groupType))
	
	return groupName, groupType, nil
}

// validateGroupIsNotPredefined validates that a group is not a PREDEFINED type (which is actually a role).
func validateGroupIsNotPredefined(groupName, groupType, operation string) error {
	if groupType == "PREDEFINED" {
		return fmt.Errorf("baton-oracle-fccs: cannot %s group membership: '%s' is a predefined Oracle Cloud role, not a group. Predefined roles (like 'Power User', 'Service Administrator', 'User', 'Viewer') appear as groups in FCCS but cannot be used in group operations. Please manage the role directly instead", operation, groupName)
	}
	return nil
}

// Grant adds a principal (user or group) to a group.
// Implements GrantProvisionerV2 for ResourceProvisionerV2.
// resource is the principal (user or group being added), entitlement contains the group resource.
func (g *groupResourceType) Grant(ctx context.Context, resource *v2.Resource, entitlement *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	startTime := time.Now()
	
	// The resource parameter is the principal (user or group being added to the group)
	principalType := resource.Id.ResourceType
	principalID := resource.Id.Resource
	
	// The entitlement contains the group resource
	groupResource := entitlement.GetResource()
	if err := validateGroupResourceType(groupResource, "grant"); err != nil {
		l := ctxzap.Extract(ctx)
		l.Error("invalid resource type for group membership grant",
			zap.String("group_resource_id", groupResource.Id.Resource),
			zap.String("group_resource_display_name", groupResource.DisplayName),
			zap.String("entitlement_id", entitlement.Id))
		return nil, nil, err
	}
	
	groupNameFromResource := groupResource.Id.Resource
	
	// Get group from cache or API
	groupName, groupType, err := g.getGroupFromCacheOrAPI(ctx, groupNameFromResource, "grant")
	if err != nil {
		return nil, nil, fmt.Errorf("baton-oracle-fccs: failed to get group: %w", err)
	}
	
	// Validate that this is not a PREDEFINED type group
	if err := validateGroupIsNotPredefined(groupName, groupType, "grant"); err != nil {
		l := ctxzap.Extract(ctx)
		l.Error("cannot grant membership to predefined role",
			zap.String("group_name", groupName),
			zap.String("group_type", groupType),
			zap.String("principal_type", principalType),
			zap.String("principal_id", principalID))
		return nil, nil, err
	}
	
	l := ctxzap.Extract(ctx)
	l.Info("granting group membership",
		zap.String("group_name", groupName),
		zap.String("group_type", groupType),
		zap.String("principal_type", principalType),
		zap.String("principal_id", principalID),
		zap.Time("start_time", startTime))
	
	switch principalType {
	case "user":
		err = g.client.AddUserToGroup(ctx, groupName, principalID)
	case "group":
		err = g.client.AddGroupToGroup(ctx, groupName, principalID)
	default:
		return nil, nil, fmt.Errorf("baton-oracle-fccs: unsupported principal type for group membership: %s (only users and groups are supported)", principalType)
	}
	
	if err != nil {
		l.Error("failed to grant group membership",
			zap.Error(err),
			zap.String("group_name", groupName),
			zap.String("group_type", groupType),
			zap.String("principal_type", principalType),
			zap.String("principal_id", principalID))
		return nil, nil, fmt.Errorf("baton-oracle-fccs: failed to grant group membership to %s %s: %w", principalType, principalID, err)
	}
	
	duration := time.Since(startTime)
	l.Info("successfully granted group membership",
		zap.String("group_name", groupName),
		zap.String("group_type", groupType),
		zap.String("principal_type", principalType),
		zap.String("principal_id", principalID),
		zap.Duration("duration", duration))
	
	// Create and return the grant
	grant := grantSdk.NewGrant(
		groupResource,
		entitlement.Id,
		resource.Id,
	)
	
	return []*v2.Grant{grant}, nil, nil
}

// Revoke removes a principal (user or group) from a group.
// Implements RevokeProvisioner for ResourceProvisionerV2.
func (g *groupResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	startTime := time.Now()
	
	groupResource := grant.Entitlement.Resource
	if err := validateGroupResourceType(groupResource, "revoke"); err != nil {
		l := ctxzap.Extract(ctx)
		l.Error("invalid resource type for group membership revocation",
			zap.String("group_resource_id", groupResource.Id.Resource),
			zap.String("group_resource_display_name", groupResource.DisplayName),
			zap.String("grant_id", grant.Id))
		return nil, err
	}
	
	groupNameFromResource := groupResource.Id.Resource
	
	// Get group from cache or API
	groupName, groupType, err := g.getGroupFromCacheOrAPI(ctx, groupNameFromResource, "revoke")
	if err != nil {
		return nil, fmt.Errorf("baton-oracle-fccs: failed to get group: %w", err)
	}
	
	principal := grant.Principal
	if principal == nil {
		return nil, fmt.Errorf("baton-oracle-fccs: grant must have a principal")
	}
	principalType := principal.Id.ResourceType
	principalID := principal.Id.Resource
	
	// Validate that this is not a PREDEFINED type group
	if err := validateGroupIsNotPredefined(groupName, groupType, "revoke"); err != nil {
		l := ctxzap.Extract(ctx)
		l.Error("cannot revoke membership from predefined role",
			zap.String("group_name", groupName),
			zap.String("group_type", groupType),
			zap.String("principal_type", principalType),
			zap.String("principal_id", principalID))
		return nil, err
	}
	
	l := ctxzap.Extract(ctx)
	l.Info("revoking group membership",
		zap.String("group_name", groupName),
		zap.String("group_type", groupType),
		zap.String("principal_type", principalType),
		zap.String("principal_id", principalID),
		zap.Time("start_time", startTime))
	
	switch principalType {
	case "user":
		err = g.client.RemoveUserFromGroup(ctx, groupName, principalID)
	case "group":
		err = g.client.RemoveGroupFromGroup(ctx, groupName, principalID)
	default:
		return nil, fmt.Errorf("baton-oracle-fccs: unsupported principal type for group membership revocation: %s (only users and groups are supported)", principalType)
	}
	
	if err != nil {
		l.Error("failed to revoke group membership",
			zap.Error(err),
			zap.String("group_name", groupName),
			zap.String("group_type", groupType),
			zap.String("principal_type", principalType),
			zap.String("principal_id", principalID))
		return nil, fmt.Errorf("baton-oracle-fccs: failed to revoke group membership from %s %s: %w", principalType, principalID, err)
	}
	
	duration := time.Since(startTime)
	l.Info("successfully revoked group membership",
		zap.String("group_name", groupName),
		zap.String("group_type", groupType),
		zap.String("principal_type", principalType),
		zap.String("principal_id", principalID),
		zap.Duration("duration", duration))
	
	return nil, nil
}
