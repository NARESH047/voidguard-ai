import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
  waitlist: defineTable({
    email: v.string(),
    repositoryUrl: v.string(),
    source: v.literal("landing_page"),
    status: v.union(v.literal("queued"), v.literal("contacted")),
  }).index("by_email", ["email"]),
});
