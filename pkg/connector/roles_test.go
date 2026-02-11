package connector

import (
	"context"
	"testing"

	"github.com/conductorone/baton-oracle-fccs/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	entitlementSdk "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoleResourceSyncer_Grants_WithGroupAssignments(t *testing.T) {
	ctx := context.Background()
	apiClient := &client.Client{} // Mock client - we'll use cached data
	syncer := roleBuilder(apiClient)

	// Setup: Create a role resource
	roleResource, err := resourceSdk.NewResource(
		"Admin",
		resourceSdk.NewResourceType("role", []v2.ResourceType_Trait{}),
		"Admin",
	)
	require.NoError(t, err)

	// Setup: Populate cache with group role assignments
	syncer.groupAssignmentsCache = map[string][]string{
		"Admin": {"AdminGroup"},
	}
	syncer.userAssignmentsCache = map[string][]string{
		"Admin": {"user1"}, // Also has a direct user assignment
	}
	syncer.cachePopulated = true

	// Execute: Get grants for the role
	grants, _, err := syncer.Grants(ctx, roleResource, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, grants, 2) // One user grant + one group grant

	// Verify: Find the group grant
	var groupGrant *v2.Grant
	for _, grant := range grants {
		if grant.GetPrincipal().GetId().GetResourceType() == "group" {
			groupGrant = grant
			break
		}
	}
	require.NotNil(t, groupGrant, "should have a group grant")

	// Verify: Check that GrantExpandable annotation is present
	annos := annotations.Annotations(groupGrant.GetAnnotations())
	expandable := &v2.GrantExpandable{}
	ok, err := annos.Pick(expandable)
	require.NoError(t, err)
	require.True(t, ok, "group grant should have GrantExpandable annotation")

	// Verify: Check the entitlement ID points to the group's member entitlement
	require.Len(t, expandable.GetEntitlementIds(), 1)
	expectedEntitlementID := entitlementSdk.NewEntitlementID(
		&v2.Resource{
			Id: &v2.ResourceId{
				ResourceType: resourceSdk.NewResourceType("group", []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP}).Id,
				Resource:     "AdminGroup",
			},
		},
		"member",
	)
	assert.Equal(t, expectedEntitlementID, expandable.GetEntitlementIds()[0])

	// Verify: Check resource type filter is set to "user"
	require.Len(t, expandable.GetResourceTypeIds(), 1)
	userResourceTypeID := resourceSdk.NewResourceType("user", []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER}).Id
	assert.Equal(t, userResourceTypeID, expandable.GetResourceTypeIds()[0])

	// Verify: Check shallow is false (allows transitive expansion)
	assert.False(t, expandable.GetShallow(), "shallow should be false to allow transitive expansion")
}

func TestRoleResourceSyncer_Grants_UserGrantsNoAnnotation(t *testing.T) {
	ctx := context.Background()
	apiClient := &client.Client{}
	syncer := roleBuilder(apiClient)

	// Setup: Create a role resource
	roleResource, err := resourceSdk.NewResource(
		"Viewer",
		resourceSdk.NewResourceType("role", []v2.ResourceType_Trait{}),
		"Viewer",
	)
	require.NoError(t, err)

	// Setup: Populate cache with only user role assignments (no group assignments)
	syncer.userAssignmentsCache = map[string][]string{
		"Viewer": {"user1"},
	}
	syncer.groupAssignmentsCache = map[string][]string{} // No group assignments
	syncer.cachePopulated = true

	// Execute: Get grants for the role
	grants, _, err := syncer.Grants(ctx, roleResource, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, grants, 1) // Only user grant

	// Verify: User grant should NOT have GrantExpandable annotation
	userGrant := grants[0]
	annos := annotations.Annotations(userGrant.GetAnnotations())
	expandable := &v2.GrantExpandable{}
	ok, err := annos.Pick(expandable)
	require.NoError(t, err)
	assert.False(t, ok, "user grant should NOT have GrantExpandable annotation")
}

