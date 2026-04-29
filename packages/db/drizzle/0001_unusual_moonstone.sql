CREATE TABLE "user_sessions" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"family_id" uuid NOT NULL,
	"refresh_token_hash" "bytea" NOT NULL,
	"prev_token_id" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"used_at" timestamp with time zone,
	"revoked_at" timestamp with time zone,
	"user_agent_family" text,
	"ip_hash" "bytea",
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "invite_codes" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"code_hash" "bytea" NOT NULL,
	"email" text NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"redeemed_at" timestamp with time zone,
	"redeemed_user_id" uuid
);
--> statement-breakpoint
ALTER TABLE "users" DROP CONSTRAINT "users_email_unique";--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "argon2_secret_key_hash" "bytea" NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "server_argon_salt" "bytea" NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "argon2_params" jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "user_argon_salt" "bytea" NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "wrapped_master_dek" "bytea" NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "wrapped_master_dek_recovery" "bytea" NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "recovery_hmac" "bytea" NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "user_pub_key" "bytea" NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "wrapped_user_signing_sk" "bytea" NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "wrapped_user_kx_sk" "bytea" NOT NULL;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "updated_at" timestamp with time zone DEFAULT now() NOT NULL;--> statement-breakpoint
ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "user_sessions" ADD CONSTRAINT "user_sessions_prev_token_id_user_sessions_id_fk" FOREIGN KEY ("prev_token_id") REFERENCES "public"."user_sessions"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "invite_codes" ADD CONSTRAINT "invite_codes_redeemed_user_id_users_id_fk" FOREIGN KEY ("redeemed_user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "user_sessions_refresh_hash_idx" ON "user_sessions" USING btree ("refresh_token_hash");--> statement-breakpoint
CREATE INDEX "user_sessions_user_active_idx" ON "user_sessions" USING btree ("user_id") WHERE revoked_at IS NULL;--> statement-breakpoint
CREATE INDEX "user_sessions_family_idx" ON "user_sessions" USING btree ("family_id");--> statement-breakpoint
CREATE UNIQUE INDEX "invite_codes_code_hash_idx" ON "invite_codes" USING btree ("code_hash");--> statement-breakpoint
CREATE INDEX "invite_codes_email_lower_idx" ON "invite_codes" USING btree (lower("email"));--> statement-breakpoint
CREATE INDEX "invite_codes_outstanding_idx" ON "invite_codes" USING btree ("expires_at") WHERE redeemed_at IS NULL;--> statement-breakpoint
CREATE UNIQUE INDEX "users_email_lower_idx" ON "users" USING btree (lower("email"));--> statement-breakpoint
CREATE UNIQUE INDEX "users_recovery_hmac_idx" ON "users" USING btree ("recovery_hmac");