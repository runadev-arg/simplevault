import { Controller, Get } from "@nestjs/common";
import type { HealthResponse } from "@simplevault/shared/zod";

import { HealthService } from "./health.service.js";

@Controller("health")
export class HealthController {
  constructor(private readonly health: HealthService) {}

  @Get()
  async check(): Promise<HealthResponse> {
    return this.health.check();
  }
}
