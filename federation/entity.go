// Copyright Franklin "Snaipe" Mathieu.
//
// Use of this source code is governed by the MIT license that can be
// found in the LICENSE file.

package federation

import (
	"crypto"
	"encoding/json"
	"time"
)

// EntityStatement is the core data structure in OIDC Federation.
// It's a signed JWT describing an entity's metadata and trust relationships.
// Two flavors: Entity Configuration (self-issued, iss==sub) and
// Subordinate Statement (issued by a superior about a subordinate).
type EntityStatement struct {
	Issuer         string          `json:"iss"`
	Subject        string          `json:"sub"`
	IssuedAt       int64           `json:"iat"`
	ExpiresAt      int64           `json:"exp"`
	JWKS           json.RawMessage `json:"jwks"`
	AuthorityHints []string        `json:"authority_hints,omitempty"`
	Metadata       *EntityMetadata `json:"metadata,omitempty"`
	MetadataPolicy json.RawMessage `json:"metadata_policy,omitempty"`
	Constraints    *Constraints    `json:"constraints,omitempty"`
	TrustMarks     json.RawMessage `json:"trust_marks,omitempty"`
	SourceEndpoint string          `json:"source_endpoint,omitempty"`

	rawToken string // the original JWT string, for signature verification
}

func (es *EntityStatement) IsExpired() bool {
	return time.Now().Unix() > es.ExpiresAt
}

func (es *EntityStatement) IsConfiguration() bool {
	return es.Issuer == es.Subject
}

// EntityMetadata holds per-entity-type metadata. Each field corresponds
// to a protocol role the entity plays.
type EntityMetadata struct {
	OpenIDProvider       json.RawMessage `json:"openid_provider,omitempty"`
	OpenIDRelyingParty   json.RawMessage `json:"openid_relying_party,omitempty"`
	OAuthClient          json.RawMessage `json:"oauth_client,omitempty"`
	OAuthResource        json.RawMessage `json:"oauth_resource,omitempty"`
	FederationEntity     *FederationEntityMetadata `json:"federation_entity,omitempty"`
}

// FederationEntityMetadata is the metadata for the federation entity itself
// (as opposed to its protocol roles).
type FederationEntityMetadata struct {
	FederationFetchEndpoint   string `json:"federation_fetch_endpoint,omitempty"`
	FederationListEndpoint    string `json:"federation_list_endpoint,omitempty"`
	FederationResolveEndpoint string `json:"federation_resolve_endpoint,omitempty"`
	OrganizationName          string `json:"organization_name,omitempty"`
	HomepageURI               string `json:"homepage_uri,omitempty"`
}

// Constraints are restrictions a superior places on subordinates.
type Constraints struct {
	MaxPathLength   *int     `json:"max_path_length,omitempty"`
	NamingConstraints *NamingConstraints `json:"naming_constraints,omitempty"`
	AllowedEntityTypes []string `json:"allowed_entity_types,omitempty"`
}

type NamingConstraints struct {
	Permitted []string `json:"permitted,omitempty"`
	Excluded  []string `json:"excluded,omitempty"`
}

// TrustAnchor is a pre-configured root of trust.
type TrustAnchor struct {
	EntityID string
	Keys     []crypto.PublicKey
}

// TrustChain is a validated chain from a leaf entity to a trust anchor.
// The chain is ordered: [leaf entity config, subordinate statement by
// intermediate about leaf, ..., trust anchor entity config].
type TrustChain struct {
	Anchor     *TrustAnchor
	Statements []*EntityStatement
	ResolvedMetadata *EntityMetadata
}
