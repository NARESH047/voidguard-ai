import OpenAI from 'openai';

const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
const gatewayId = process.env.CLOUDFLARE_GATEWAY_ID;

export const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  baseURL: `https://gateway.ai.cloudflare.com/v1/${accountId}/${gatewayId}/openai`,
});

export const hermes = new OpenAI({
  apiKey: process.env.OPENROUTER_API_KEY,
  baseURL: `https://gateway.ai.cloudflare.com/v1/${accountId}/${gatewayId}/openrouter`,
  defaultHeaders: {
    "HTTP-Referer": "http://localhost:3000",
    "X-Title": "Hermes Buildathon Sprint",
  }
});

export const HERMES_MODEL = "nousresearch/hermes-3-llama-3.1-405b";

export async function searchLiveWeb(query: string) {
  if (!process.env.LINKUP_API_KEY) throw new Error("Missing Linkup API Key");
  
  const response = await fetch('https://api.linkup.ai/v1/search', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${process.env.LINKUP_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ query, depth: 'standard' })
  });
  
  if (!response.ok) throw new Error(`Linkup API failure: ${response.statusText}`);
  return response.json();
}
