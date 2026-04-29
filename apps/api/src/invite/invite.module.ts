import { Module } from "@nestjs/common";

import { InviteController } from "./invite.controller.js";
import { InviteService } from "./invite.service.js";

@Module({
  controllers: [InviteController],
  providers: [InviteService],
  exports: [InviteService],
})
export class InviteModule {}
