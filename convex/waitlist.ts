import { mutation } from "./_generated/server";
import { v } from "convex/values";

const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

function validateRepositoryUrl(repositoryUrl: string) {
  try {
    const url = new URL(repositoryUrl);
    const hostname = url.hostname.toLowerCase();
    if (url.protocol !== "https:" || !["github.com", "www.github.com"].includes(hostname)) {
      throw new Error("Enter a valid HTTPS GitHub repository URL.");
    }
    if (url.pathname.split("/").filter(Boolean).length < 2) {
      throw new Error("Enter a repository URL in the form https://github.com/owner/repository.");
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("Enter a")) throw error;
    throw new Error("Enter a valid HTTPS GitHub repository URL.");
  }
}

export const join = mutation({
  args: {
    email: v.string(),
    repositoryUrl: v.string(),
    source: v.literal("landing_page"),
  },
  handler: async (ctx, args) => {
    const email = args.email.trim().toLowerCase();
    const repositoryUrl = args.repositoryUrl.trim();

    if (!EMAIL_PATTERN.test(email) || email.length > 320) {
      throw new Error("Enter a valid email address.");
    }
    validateRepositoryUrl(repositoryUrl);

    const existing = await ctx.db
      .query("waitlist")
      .withIndex("by_email", (query) => query.eq("email", email))
      .unique();

    if (existing) {
      await ctx.db.patch(existing._id, { repositoryUrl });
      return { id: existing._id, alreadyJoined: true };
    }

    const id = await ctx.db.insert("waitlist", {
      email,
      repositoryUrl,
      source: args.source,
      status: "queued",
    });

    return { id, alreadyJoined: false };
  },
});
