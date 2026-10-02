import { NextResponse } from 'next/server';

export async function GET() {
  return NextResponse.json({
    hasClientId: !!process.env.NEXT_PUBLIC_OKTA_CLIENT_ID,
    clientIdLength: process.env.NEXT_PUBLIC_OKTA_CLIENT_ID?.length || 0,
    hasAgentPrivateKey: !!process.env.OKTA_AI_AGENT_PRIVATE_KEY,
    hasIssuer: !!process.env.NEXT_PUBLIC_OKTA_ISSUER,
    issuer: process.env.NEXT_PUBLIC_OKTA_ISSUER || 'NOT SET',
    hasDomain: !!process.env.NEXT_PUBLIC_OKTA_DOMAIN,
    domain: process.env.NEXT_PUBLIC_OKTA_DOMAIN || 'NOT SET',
    hasNextAuthSecret: !!process.env.NEXTAUTH_SECRET,
    hasNextAuthUrl: !!process.env.NEXTAUTH_URL,
    nextAuthUrl: process.env.NEXTAUTH_URL || 'NOT SET',
    hasApiUrl: !!process.env.NEXT_PUBLIC_API_URL,
    apiUrl: process.env.NEXT_PUBLIC_API_URL || 'NOT SET (will use localhost:8000)',
  });
}
