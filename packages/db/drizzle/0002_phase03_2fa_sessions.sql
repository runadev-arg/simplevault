-- ----------------------------------------------------------------------------
-- Pre-flight: defensive guard for FINDING-0017 email length cap (varchar(254)).
-- Aborts the migration BEFORE any destructive change if any existing row
-- holds an email > 254 chars. At Phase-02 close cardinality (≤50 users) this
-- is paranoid-safe but cheap; the `USING substring(email,1,254)` cast below
-- is itself idempotent for our cardinality. Kept as a hard fail-fast.
-- ----------------------------------------------------------------------------
DO $$
BEGIN
	IF EXISTS (SELECT 1 FROM users WHERE length(email) > 254) THEN
		RAISE EXCEPTION 'pre-existing users.email > 254 chars — refusing migration (FINDING-0017 guard)';
	END IF;
	IF EXISTS (SELECT 1 FROM invite_codes WHERE length(email) > 254) THEN
		RAISE EXCEPTION 'pre-existing invite_codes.email > 254 chars — refusing migration (FINDING-0017 guard)';
	END IF;
END $$;
--> statement-breakpoint
CREATE TABLE "webauthn_credentials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"credential_id" "bytea" NOT NULL,
	"public_key" "bytea" NOT NULL,
	"counter" bigint DEFAULT 0 NOT NULL,
	"transports" text[] DEFAULT '{}'::text[] NOT NULL,
	"aaguid" "bytea",
	"name" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "webauthn_challenges" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"challenge" "bytea" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL
);
--> statement-breakpoint
CREATE TABLE "totp_credentials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"user_id" uuid NOT NULL,
	"wrapped_secret" "bytea" NOT NULL,
	"encrypted_secret_aad" "bytea" NOT NULL,
	"last_used_step" bigint DEFAULT 0 NOT NULL,
	"name" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_used_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "session_epoch" integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE "webauthn_credentials" ADD CONSTRAINT "webauthn_credentials_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "webauthn_challenges" ADD CONSTRAINT "webauthn_challenges_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "totp_credentials" ADD CONSTRAINT "totp_credentials_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "webauthn_credentials_user_idx" ON "webauthn_credentials" USING btree ("user_id");--> statement-breakpoint
CREATE UNIQUE INDEX "webauthn_credentials_credential_id_idx" ON "webauthn_credentials" USING btree ("credential_id");--> statement-breakpoint
CREATE UNIQUE INDEX "webauthn_challenges_user_kind_idx" ON "webauthn_challenges" USING btree ("user_id","kind");--> statement-breakpoint
CREATE INDEX "webauthn_challenges_expires_idx" ON "webauthn_challenges" USING btree ("expires_at");--> statement-breakpoint
CREATE INDEX "totp_credentials_user_idx" ON "totp_credentials" USING btree ("user_id");--> statement-breakpoint
-- ----------------------------------------------------------------------------
-- FINDING-0017 / FINDING-0022 fold-in: tighten email columns to varchar(254).
-- USING substring(...) makes the cast idempotent for any existing row even
-- if the pre-flight DO-block above is somehow bypassed.
-- ----------------------------------------------------------------------------
ALTER TABLE "users" ALTER COLUMN "email" SET DATA TYPE varchar(254) USING substring("email", 1, 254);--> statement-breakpoint
ALTER TABLE "invite_codes" ALTER COLUMN "email" SET DATA TYPE varchar(254) USING substring("email", 1, 254);