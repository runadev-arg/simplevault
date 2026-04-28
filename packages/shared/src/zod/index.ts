import { z } from "zod";

export const HealthResponseSchema = z.object({
  status: z.enum(["ok", "degraded", "down"]),
  db: z.enum(["ok", "down"]),
  redis: z.enum(["ok", "down"]),
  timestamp: z.string().datetime(),
});

export type HealthResponse = z.infer<typeof HealthResponseSchema>;
