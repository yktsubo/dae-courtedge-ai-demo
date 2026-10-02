import type { NextAuthOptions } from 'next-auth';
import type { OAuthConfig } from 'next-auth/providers/oauth';
import { createPrivateKeyJwtTokenRequest } from './okta-private-key-jwt';

interface OktaProfile {
  sub: string;
  name?: string;
  preferred_username?: string;
  email?: string;
  picture?: string;
}

const OKTA_CLIENT_ID = process.env.OKTA_CLIENT_ID || process.env.NEXT_PUBLIC_OKTA_CLIENT_ID!;
const OKTA_ISSUER = process.env.NEXT_PUBLIC_OKTA_ISSUER!;

// Okta allows a single client authentication method per client_id, and the backend
// token exchange requires private_key_jwt, so login must use it as well.
// clientSecret is required by the next-auth v4 types but is never sent: the token
// request is overridden below and the profile is read from the ID token (no userinfo call).
const UNUSED_CLIENT_SECRET = 'unused-private-key-jwt-is-used-instead';

const oktaProvider: OAuthConfig<OktaProfile> = {
  id: 'okta',
  name: 'Okta',
  type: 'oauth',
  wellKnown: `${OKTA_ISSUER}/.well-known/openid-configuration`,
  clientId: OKTA_CLIENT_ID,
  clientSecret: UNUSED_CLIENT_SECRET,
  // 'none' keeps openid-client from ever sending the dummy secret; auth is done in token.request.
  client: { token_endpoint_auth_method: 'none' },
  authorization: { params: { scope: 'openid email profile' } },
  token: { request: createPrivateKeyJwtTokenRequest(OKTA_CLIENT_ID) },
  checks: ['pkce', 'state'],
  idToken: true,
  profile(profile) {
    return {
      id: profile.sub,
      name: profile.name ?? profile.preferred_username,
      email: profile.email,
      image: profile.picture,
    };
  },
};

export const authOptions: NextAuthOptions = {
  providers: [
    oktaProvider,
  ],
  pages: {
    signIn: '/auth/signin',
  },
  callbacks: {
    async jwt({ token, account }) {
      if (account) {
        token.accessToken = account.access_token;
        token.idToken = account.id_token;
      }
      return token;
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken as string;
      session.idToken = token.idToken as string;
      session.user = {
        ...session.user,
        id: token.sub as string,
      };
      return session;
    },
  },
  secret: process.env.NEXTAUTH_SECRET,
  debug: true,
};
