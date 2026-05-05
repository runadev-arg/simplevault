CREATE TABLE "vaults" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"owner_user_id" uuid NOT NULL,
	"kind" text DEFAULT 'personal' NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "vaults_kind_check" CHECK ("vaults"."kind" IN ('personal','shared'))
);
--> statement-breakpoint
CREATE TABLE "credentials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"vault_id" uuid NOT NULL,
	"version" integer DEFAULT 1 NOT NULL,
	"ciphertext" "bytea" NOT NULL,
	"nonce" "bytea" NOT NULL,
	"aad_params_json" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "vaults" ADD CONSTRAINT "vaults_owner_user_id_users_id_fk" FOREIGN KEY ("owner_user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_vault_id_vaults_id_fk" FOREIGN KEY ("vault_id") REFERENCES "public"."vaults"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "vaults_owner_personal_uidx" ON "vaults" USING btree ("owner_user_id") WHERE "vaults"."kind" = 'personal';--> statement-breakpoint
CREATE INDEX "credentials_vault_idx" ON "credentials" USING btree ("vault_id");--> statement-breakpoint
-- ----------------------------------------------------------------------------
-- Phase 04 backfill: every existing user gets exactly one personal vault.
-- Idempotent: re-running this migration on an already-migrated DB is a no-op
-- because of the WHERE NOT EXISTS clause AND the unique partial index above.
-- (Key Link 10 — closes the gap between Phase-03 fixture DBs and Phase-04
-- handlers that assume a personal vault row exists for every user.)
-- ----------------------------------------------------------------------------
INSERT INTO "vaults" ("owner_user_id", "kind")
SELECT "id", 'personal' FROM "users"
WHERE NOT EXISTS (
	SELECT 1 FROM "vaults" v
	WHERE v."owner_user_id" = "users"."id" AND v."kind" = 'personal'
);