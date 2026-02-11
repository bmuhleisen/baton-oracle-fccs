package connector

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/conductorone/baton-oracle-fccs/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	resourceSdk "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const maxErrorsToLog = 3

// userResourceType syncs user resources from Oracle FCCS.
type userResourceType struct {
	client *client.Client
}

// userBuilder creates a new user resource syncer.
func userBuilder(c *client.Client) *userResourceType {
	return &userResourceType{
		client: c,
	}
}

// ResourceType returns the resource type for users.
func (u *userResourceType) ResourceType(ctx context.Context) *v2.ResourceType {
	return resourceTypeUser
}

// List returns all users from Oracle FCCS.
// Note: The Oracle EPM API does not support pagination for the users list endpoint.
func (u *userResourceType) List(ctx context.Context, parentResourceID *v2.ResourceId, opts resourceSdk.SyncOpAttrs) ([]*v2.Resource, *resourceSdk.SyncOpResults, error) {
	startTime := time.Now()
	l := ctxzap.Extract(ctx)
	l.Info("listing users", zap.Time("start_time", startTime))

	// Check if we've already fetched all users (no pagination support)
	if opts.PageToken.Token != "" {
		// We've already returned all users, nothing more to fetch
		return nil, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, nil
	}

	users, rateLimit, err := u.client.ListUsers(ctx)
	if err != nil {
		l.Error("failed to list users", zap.Error(err))
		return nil, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, fmt.Errorf("baton-oracle-fccs: failed to list users: %w", err)
	}

	var resources []*v2.Resource
	var errors []error
	for _, user := range users {
		// Check for context cancellation to allow early termination
		if ctx.Err() != nil {
			return nil, nil, ctx.Err()
		}

		userCopy := user // Create a copy to avoid pointer issues
		userResource, err := u.userToResource(ctx, &userCopy)
		if err != nil {
			l.Warn("failed to convert user to resource, skipping",
				zap.Error(err),
				zap.String("user_login", user.UserLogin))
			errors = append(errors, fmt.Errorf("baton-oracle-fccs: user %s: %w", user.UserLogin, err))
			continue // Continue processing other users instead of failing entire sync
		}
		resources = append(resources, userResource)
	}
	
	if len(errors) > 0 {
		l.Warn("some users failed to convert",
			zap.Int("failed_count", len(errors)),
			zap.Int("success_count", len(resources)))
		// Log first few errors
		for i, err := range errors {
			if i < maxErrorsToLog {
				l.Debug("conversion error", zap.Error(err))
			}
		}
	}

	duration := time.Since(startTime)
	l.Info("successfully listed users", 
		zap.Int("count", len(resources)),
		zap.Duration("duration", duration),
		zap.Int("errors", len(errors)))
	
	var annos annotations.Annotations
	if rateLimit != nil {
		annos.WithRateLimiting(rateLimit)
	}
	// Return empty string for next token since there's no pagination
	return resources, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: annos}, nil
}

// Entitlements returns the entitlements for a user.
func (u *userResourceType) Entitlements(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Entitlement, *resourceSdk.SyncOpResults, error) {
	return nil, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, nil
}

// Grants returns the grants for a user.
func (u *userResourceType) Grants(ctx context.Context, resource *v2.Resource, opts resourceSdk.SyncOpAttrs) ([]*v2.Grant, *resourceSdk.SyncOpResults, error) {
	return nil, &resourceSdk.SyncOpResults{NextPageToken: "", Annotations: nil}, nil
}

func (u *userResourceType) userToResource(ctx context.Context, user *client.User) (*v2.Resource, error) {
	profile := map[string]interface{}{
		"user_login": user.UserLogin,
		"first_name": user.FirstName,
		"last_name":  user.LastName,
		"email":      user.Email,
	}
	// Note: Group memberships and role assignments are not included here.
	// They are fetched via User Group Report and Role Assignment Report for grants.

	userTraitOptions := []resourceSdk.UserTraitOption{
		resourceSdk.WithUserProfile(profile),
		resourceSdk.WithUserLogin(user.UserLogin),
		// The Oracle EPM API doesn't return status in list users response
		resourceSdk.WithStatus(v2.UserTrait_Status_STATUS_ENABLED),
	}

	if user.Email != "" {
		userTraitOptions = append(userTraitOptions, resourceSdk.WithEmail(user.Email, true))
	}

	displayName := strings.TrimSpace(fmt.Sprintf("%s %s", user.FirstName, user.LastName))
	if displayName == "" {
		displayName = user.UserLogin
	}

	resourceType := u.ResourceType(ctx)
	resource, err := resourceSdk.NewUserResource(
		displayName,
		resourceType,
		user.UserLogin,
		userTraitOptions,
	)
	if err != nil {
		return nil, fmt.Errorf("baton-oracle-fccs: failed to create user resource: %w", err)
	}

	return resource, nil
}

// NOTE: Account provisioning is intentionally not supported in this connector.
// User lifecycle operations are managed by the dedicated IDCS connector; this connector
// focuses on FCCS users/groups/roles sync and FCCS role/group assignment only.
