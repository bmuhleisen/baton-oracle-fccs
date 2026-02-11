package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	baseURLField = field.StringField(
		"base-url",
		field.WithRequired(true),
		field.WithDisplayName("Base URL"),
		field.WithDescription("The base URL of your Oracle FCCS instance (e.g., https://example.epm.us2.oraclecloud.com)"),
	)
	oauthClientIDField = field.StringField(
		"oracle-client-id",
		field.WithRequired(true),
		field.WithDisplayName("Oracle Client ID"),
		field.WithDescription("Oracle IDCS OAuth client ID for the confidential application"),
	)
	oauthClientSecretField = field.StringField(
		"oracle-client-secret",
		field.WithRequired(true),
		field.WithDisplayName("Oracle Client Secret"),
		field.WithDescription("Oracle IDCS OAuth client secret"),
		field.WithIsSecret(true),
	)
	tokenURLField = field.StringField(
		"token-url",
		field.WithRequired(true),
		field.WithDisplayName("Token URL"),
		field.WithDescription("The Oracle IDCS OAuth2 token URL (e.g., https://<idcs-tenant>.identity.oraclecloud.com/oauth2/v1/token)"),
	)
	// JWT User Assertion fields
	jwtPrivateKeyField = field.StringField(
		"jwt-private-key",
		field.WithDisplayName("JWT Private Key"),
		field.WithDescription("Private key (PEM or base64-encoded PEM) for JWT user assertion. Certificate must be uploaded to IDCS Security → Trusted Partner Certificates."),
		field.WithIsSecret(true),
	)
	jwtSubjectField = field.StringField(
		"jwt-subject",
		field.WithDisplayName("JWT Subject"),
		field.WithDescription("The username to impersonate in the JWT assertion (sub claim)."),
	)
	jwtKeyIDField = field.StringField(
		"jwt-key-id",
		field.WithDisplayName("JWT Key ID"),
		field.WithDescription("Certificate alias (kid) matching the uploaded certificate in IDCS."),
	)
	jwtIssuerField = field.StringField(
		"jwt-issuer",
		field.WithDisplayName("JWT Issuer"),
		field.WithDescription("JWT issuer claim (defaults to oracle-client-id)."),
	)
	jwtAudienceField = field.StringField(
		"jwt-audience",
		field.WithDisplayName("JWT Audience"),
		field.WithDescription("JWT audience claim (defaults to https://identity.oraclecloud.com/)."),
	)
	scopeField = field.StringField(
		"scope",
		field.WithDisplayName("Scope"),
		field.WithDescription("OAuth2 scope for the token request (e.g., urn:opc:idm:__myscopes__)."),
	)
	fieldRelationships = []field.SchemaFieldRelationship{
		// JWT requires both private key and subject
		field.FieldsRequiredTogether(jwtPrivateKeyField, jwtSubjectField),
	}
)

//go:generate go run ./gen
var Config = field.NewConfiguration(
	[]field.SchemaField{
		// Required fields
		baseURLField,
		oauthClientIDField,
		oauthClientSecretField,
		tokenURLField,
		// JWT User Assertion authentication
		jwtPrivateKeyField,
		jwtSubjectField,
		jwtKeyIDField,
		jwtIssuerField,
		jwtAudienceField,
		// Optional
		scopeField,
	},
	field.WithConstraints(fieldRelationships...),
	field.WithConnectorDisplayName("Oracle FCCS"),
	field.WithHelpUrl("/docs/baton/oracle-fccs"),
)
