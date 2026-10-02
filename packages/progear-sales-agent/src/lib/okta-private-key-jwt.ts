import { randomUUID } from 'crypto';
import { SignJWT, createRemoteJWKSet, importJWK, jwtVerify, type JWK } from 'jose';
import type { TokenSetParameters } from 'openid-client';
import type { TokenEndpointHandler } from 'next-auth/providers/oauth';

// RFC 7523 client authentication (private_key_jwt) for the Okta token endpoint.
// The same JWK is used by the backend for ID-JAG token exchange.

const CLIENT_ASSERTION_TYPE = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer';
const ASSERTION_LIFETIME_SECONDS = 300;
const DEFAULT_SIGNING_ALG = 'RS256';

type TokenRequest = NonNullable<TokenEndpointHandler['request']>;

let jwksCache: { uri: string; jwks: ReturnType<typeof createRemoteJWKSet> } | null = null;

function loadPrivateJwk(): JWK {
  const raw = process.env.OKTA_AI_AGENT_PRIVATE_KEY;
  if (!raw) {
    throw new Error('OKTA_AI_AGENT_PRIVATE_KEY is not set (required for private_key_jwt login)');
  }
  try {
    return JSON.parse(raw) as JWK;
  } catch {
    // Never log the raw value: it is a private key.
    throw new Error('OKTA_AI_AGENT_PRIVATE_KEY is not valid JSON');
  }
}

export async function createClientAssertion(clientId: string, audience: string): Promise<string> {
  const jwk = loadPrivateJwk();
  const alg = jwk.alg ?? DEFAULT_SIGNING_ALG;
  const key = await importJWK(jwk, alg);
  const now = Math.floor(Date.now() / 1000);

  return new SignJWT({})
    .setProtectedHeader({ alg, ...(jwk.kid ? { kid: jwk.kid } : {}) })
    .setIssuer(clientId)
    .setSubject(clientId)
    .setAudience(audience)
    .setJti(randomUUID())
    .setIssuedAt(now)
    .setExpirationTime(now + ASSERTION_LIFETIME_SECONDS)
    .sign(key);
}

function getRemoteJwks(jwksUri: string) {
  if (jwksCache?.uri !== jwksUri) {
    jwksCache = { uri: jwksUri, jwks: createRemoteJWKSet(new URL(jwksUri)) };
  }
  return jwksCache.jwks;
}

// next-auth only decodes the ID token when token.request is overridden, so verify it here.
async function verifyIdToken(idToken: string, issuer: string, jwksUri: string, clientId: string) {
  await jwtVerify(idToken, getRemoteJwks(jwksUri), { issuer, audience: clientId });
}

export function createPrivateKeyJwtTokenRequest(clientId: string): TokenRequest {
  return async ({ params, checks, client, provider }) => {
    const { token_endpoint: tokenEndpoint, jwks_uri: jwksUri, issuer } = client.issuer.metadata;
    if (!tokenEndpoint || !jwksUri) {
      throw new Error('Okta discovery document is missing token_endpoint or jwks_uri');
    }
    if (!params.code) {
      throw new Error('Authorization code is missing from the callback');
    }
    if (!checks.code_verifier) {
      throw new Error('PKCE code_verifier is missing; enable the "pkce" check');
    }

    const body = new URLSearchParams({
      grant_type: 'authorization_code',
      code: params.code,
      redirect_uri: provider.callbackUrl,
      code_verifier: checks.code_verifier,
      client_id: clientId,
      client_assertion_type: CLIENT_ASSERTION_TYPE,
      client_assertion: await createClientAssertion(clientId, tokenEndpoint),
    });

    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        Accept: 'application/json',
      },
      body,
    });
    const responseText = await response.text();

    if (!response.ok) {
      console.error(
        `[auth] Okta token endpoint returned HTTP ${response.status}: ${responseText}`,
      );
      throw new Error(`Okta token exchange failed (HTTP ${response.status})`);
    }

    const tokens = JSON.parse(responseText) as TokenSetParameters;
    if (!tokens.id_token) {
      throw new Error('Okta token response did not include an id_token');
    }
    await verifyIdToken(tokens.id_token, issuer, jwksUri, clientId);

    return { tokens };
  };
}
