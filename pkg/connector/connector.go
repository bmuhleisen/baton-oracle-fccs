package connector

import (
	"context"
	"fmt"
	"strings"

	cfg "github.com/conductorone/baton-oracle-fccs/pkg/config"
	"github.com/conductorone/baton-oracle-fccs/pkg/client"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
)

// OracleFCCS is the connector implementation for Oracle Financial Consolidation and Close Cloud Service.
type OracleFCCS struct {
	client *client.Client
	config *cfg.OracleFccs
}

// New creates a new Oracle FCCS connector.
func New(ctx context.Context, config *cfg.OracleFccs) (*OracleFCCS, error) {
	// Validate base URL
	if config.BaseUrl == "" {
		return nil, fmt.Errorf("baton-oracle-fccs: base-url is required")
	}
	if !strings.HasPrefix(config.BaseUrl, "http://") && !strings.HasPrefix(config.BaseUrl, "https://") {
		return nil, fmt.Errorf("baton-oracle-fccs: base-url must start with http:// or https://")
	}

	// Validate authentication configuration
	// JWT User Assertion is required
	if config.JwtPrivateKey == "" || config.JwtSubject == "" {
		return nil, fmt.Errorf("baton-oracle-fccs: JWT authentication required: jwt-private-key and jwt-subject must be provided")
	}

	apiClient, err := client.NewClient(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("baton-oracle-fccs: error creating Oracle FCCS client: %w", err)
	}

	return &OracleFCCS{
		client: apiClient,
		config: config,
	}, nil
}

// Metadata returns metadata about the Oracle FCCS connector.
// Note: Account provisioning is not supported - user lifecycle is managed by the IDCS connector.
func (o *OracleFCCS) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "Oracle FCCS",
		Description: "Connector syncing users, groups, roles, and permissions from Oracle Financial Consolidation and Close Cloud Service",
	}, nil
}

// Validate validates the connector configuration by testing the connection.
func (o *OracleFCCS) Validate(ctx context.Context) (annotations.Annotations, error) {
	// Test the connection by attempting to authenticate
	err := o.client.Authenticate(ctx)
	if err != nil {
		return nil, fmt.Errorf("baton-oracle-fccs: failed to authenticate with Oracle FCCS: %w", err)
	}

	return nil, nil
}

// ResourceSyncers returns the resource syncers for the Oracle FCCS connector.
func (o *OracleFCCS) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncerV2 {
	return []connectorbuilder.ResourceSyncerV2{
		userBuilder(o.client),
		groupBuilder(o.client),
		roleBuilder(o.client),
	}
}

