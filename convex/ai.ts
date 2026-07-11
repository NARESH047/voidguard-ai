import { action } from "./_generated/server";
import OpenAI from "openai";

declare const process: { env: Record<string, string | undefined> };

export const runLiveDiagnostic = action({
  args: {},
  handler: async () => {
    const accountId = process.env.CLOUDFLARE_ACCOUNT_ID;
    const gatewayId = process.env.CLOUDFLARE_GATEWAY_ID;
    const apiKey = process.env.OPENAI_API_KEY;
    const cfAuthToken = process.env.CLOUDFLARE_API_TOKEN;

    if (!accountId || !gatewayId || !apiKey || !cfAuthToken) {
      throw new Error("Missing credentials inside Convex environment variables.");
    }

    // Connect through the proxy passing the custom authentication header
    const openai = new OpenAI({
      apiKey: apiKey,
      baseURL: `https://gateway.ai.cloudflare.com/v1/${accountId}/${gatewayId}/openai`,
      defaultHeaders: {
        // 💡 This unlocks the front door of your Authenticated Gateway securely
        "cf-aig-authorization": `Bearer ${cfAuthToken}`,
      }
    });

    const response = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: "Ping" }],
      max_tokens: 5,
    });

    return response.choices[0].message.content ?? "Connected, but no text returned.";
  },
});