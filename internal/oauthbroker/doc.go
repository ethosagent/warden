// Package oauthbroker is the control plane's OAuth broker domain (feature
// "OAuth broker", P3): the provider registry built from consent.providers,
// the shared scope helpers and the stored token record. It runs only in the
// control plane. Workers never import it, never hold a provider client secret
// or a refresh token, and nothing here reaches /policy or the signed bundle.
package oauthbroker
