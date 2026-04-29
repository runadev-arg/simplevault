#!/usr/bin/env node
import { Command } from "commander";
import { argon2Calibrate } from "./commands/argon2-calibrate.js";
import { inviteCreate } from "./commands/invite-create.js";

const program = new Command();
program
  .name("simplevault-cli")
  .description("SimpleVault operator CLI")
  .showHelpAfterError();

const invite = program.command("invite").description("Manage invite codes");
invite
  .command("create")
  .description("Issue a single-use invite code (HMAC-bound, 7-day TTL by default)")
  .requiredOption("--email <email>", "Email address the code is bound to (lowercased)")
  .option("--ttl-days <days>", "Days until the code expires", "7")
  .option("--expires-in <days>", "Alias for --ttl-days (e.g. 7d)")
  .action(async (opts: { email: string; ttlDays?: string; expiresIn?: string }) => {
    const ttl = opts.expiresIn ?? opts.ttlDays;
    await inviteCreate(ttl !== undefined ? { email: opts.email, ttlDays: ttl } : { email: opts.email });
  });

const argon2 = program.command("argon2").description("Argon2id helpers");
argon2
  .command("calibrate")
  .description("Calibrate Argon2id params for this host (target ~750ms)")
  .action(async () => {
    await argon2Calibrate();
  });

await program.parseAsync(process.argv);
