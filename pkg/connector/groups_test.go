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

func TestGroupResourceSyncer_Grants_WithNestedGroups(t *testing.T) {
	ctx := context.Background()
	apiClient := &client.Client{} // Mock client - we'll use cached data
	syncer := groupBuilder(apiClient)

	// Setup: Create a parent group resource
	parentGroupResource, err := resourceSdk.NewGroupResource(
		"ParentGroup",
		resourceSdk.NewResourceType("group", []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP}),
		"ParentGroup",
		[]resourceSdk.GroupTraitOption{},
	)
	require.NoError(t, err)

	// Setup: Populate cache with group data that has nested groups
	syncer.groupsCache["ParentGroup"] = &client.GroupDetail{
		GroupName: "ParentGroup",
		Type:      "EPM",
		Members: &client.GroupMembers{
			Users: []client.GroupMember{
				{UserLogin: "user1"},
			},
			Groups: []client.GroupMember{
				{GroupName: "ChildGroup"},
			},
		},
	}

	// Execute: Get grants for the parent group
	grants, _, err := syncer.Grants(ctx, parentGroupResource, resourceSdk.SyncOpAttrs{})
	require.NoError(t, err)
	require.Len(t, grants, 2) // One user grant + one nested group grant

	// Verify: Find the nested group grant
	var nestedGroupGrant *v2.Grant
	for _, grant := range grants {
		if grant.GetPrincipal().GetId().GetResourceType() == "group" {
			nestedGroupGrant = grant
			break
		}
	}
	require.NotNil(t, nestedGroupGrant, "should have a nested group grant")

	// Verify: Check that GrantExpandable annotation is present
	annos := annotations.Annotations(nestedGroupGrant.GetAnnotations())
	expandable := &v2.GrantExpandable{}
	ok, err := annos.Pick(expandable)
	require.NoError(t, err)
	require.True(t, ok, "nested group grant should have GrantExpandable annotation")

	// Verify: Check the entitlement ID points to the child group's member entitlement
	require.Len(t, expandable.GetEntitlementIds(), 1)
	expectedEntitlementID := entitlementSdk.NewEntitlementID(
		&v2.Resource{
			Id: &v2.ResourceId{
				ResourceType: resourceSdk.NewResourceType("group", []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP}).Id,
				Resource:     "ChildGroup",
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

func TestGroupResourceSyncer_Grants_UserGrantsNoAnnotation(t *testing.T) {
	ctx := context.Background()
	apiClient := &client.Client{}
	syncer := groupBuilder(apiClient)

	// Setup: Create a group resource
	groupResource, err := resourceSdk.NewGroupResource(
		"TestGroup",
		resourceSdk.NewResourceType("group", []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP}),
		"TestGroup",
		[]resourceSdk.GroupTraitOption{},
	)
	require.NoError(t, err)

	// Setup: Populate cache with group data that has only users (no nested groups)
	syncer.groupsCache["TestGroup"] = &client.GroupDetail{
		GroupName: "TestGroup",
		Type:      "EPM",
		Members: &client.GroupMembers{
			Users: []client.GroupMember{
				{UserLogin: "user1"},
			},
			Groups: []client.GroupMember{}, // No nested groups
		},
	}

	// Execute: Get grants for the group
	grants, _, err := syncer.Grants(ctx, groupResource, resourceSdk.SyncOpAttrs{})
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

