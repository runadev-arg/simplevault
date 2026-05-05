CREATE TABLE "vault_memberships" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"vault_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"role" text NOT NULL,
	"status" text DEFAULT 'pending' NOT NULL,
	"wrapped_vault_key" "bytea" NOT NULL,
	"invited_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "vault_memberships_role_check" CHECK ("vault_memberships"."role" IN ('owner','member')),
	CONSTRAINT "vault_memberships_status_check" CHECK ("vault_memberships"."status" IN ('pending','active','revoked'))
);
--> statement-breakpoint
ALTER TABLE "vaults" ADD COLUMN "name" text;--> statement-breakpoint
ALTER TABLE "vault_memberships" ADD CONSTRAINT "vault_memberships_vault_id_vaults_id_fk" FOREIGN KEY ("vault_id") REFERENCES "public"."vaults"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vault_memberships" ADD CONSTRAINT "vault_memberships_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "vault_memberships" ADD CONSTRAINT "vault_memberships_invited_by_users_id_fk" FOREIGN KEY ("invited_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "vault_memberships_vault_user_uidx" ON "vault_memberships" USING btree ("vault_id","user_id");