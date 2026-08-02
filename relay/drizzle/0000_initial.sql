CREATE TABLE "accounts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"display_name" text
);
--> statement-breakpoint
ALTER TABLE "accounts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "audit_relay" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"account_id" uuid NOT NULL,
	"device_id" uuid,
	"event" text NOT NULL,
	"detail" jsonb NOT NULL,
	"remote_ip" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "audit_relay" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "devices" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"account_id" uuid NOT NULL,
	"kind" text NOT NULL,
	"display_name" text NOT NULL,
	"identity_public_key" text NOT NULL,
	"identity_algorithm" text NOT NULL,
	"noise_static_public_key" text NOT NULL,
	"noise_static_signature" text NOT NULL,
	"auth_token_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"last_seen_at" timestamp with time zone,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "devices" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "pairing_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"account_id" uuid NOT NULL,
	"agent_device_id" uuid NOT NULL,
	"routing_id" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"used" boolean DEFAULT false NOT NULL,
	"used_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "pairing_tokens" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "pairings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"account_id" uuid NOT NULL,
	"agent_device_id" uuid NOT NULL,
	"client_device_id" uuid NOT NULL,
	"agent_noise_static_public_key" text NOT NULL,
	"agent_noise_static_signature" text NOT NULL,
	"client_noise_static_public_key" text NOT NULL,
	"client_noise_static_signature" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"revoked_at" timestamp with time zone,
	"revoked_by" text
);
--> statement-breakpoint
ALTER TABLE "pairings" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "push_tokens" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"account_id" uuid NOT NULL,
	"device_id" uuid NOT NULL,
	"apns_token" text NOT NULL,
	"environment" text NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "push_tokens" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
CREATE TABLE "quotas" (
	"account_id" uuid PRIMARY KEY NOT NULL,
	"max_devices" integer NOT NULL,
	"max_pairing_attempts_per_hour" integer NOT NULL,
	"turn_bytes_per_month" bigint NOT NULL
);
--> statement-breakpoint
ALTER TABLE "quotas" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "audit_relay" ADD CONSTRAINT "audit_relay_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_relay" ADD CONSTRAINT "audit_relay_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "devices" ADD CONSTRAINT "devices_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pairing_tokens" ADD CONSTRAINT "pairing_tokens_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pairing_tokens" ADD CONSTRAINT "pairing_tokens_agent_device_id_devices_id_fk" FOREIGN KEY ("agent_device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pairings" ADD CONSTRAINT "pairings_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pairings" ADD CONSTRAINT "pairings_agent_device_id_devices_id_fk" FOREIGN KEY ("agent_device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "pairings" ADD CONSTRAINT "pairings_client_device_id_devices_id_fk" FOREIGN KEY ("client_device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "push_tokens" ADD CONSTRAINT "push_tokens_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "push_tokens" ADD CONSTRAINT "push_tokens_device_id_devices_id_fk" FOREIGN KEY ("device_id") REFERENCES "public"."devices"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "quotas" ADD CONSTRAINT "quotas_account_id_accounts_id_fk" FOREIGN KEY ("account_id") REFERENCES "public"."accounts"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_relay_account_created_idx" ON "audit_relay" USING btree ("account_id","created_at");--> statement-breakpoint
CREATE INDEX "devices_account_idx" ON "devices" USING btree ("account_id");--> statement-breakpoint
CREATE UNIQUE INDEX "devices_auth_token_hash_key" ON "devices" USING btree ("auth_token_hash");--> statement-breakpoint
CREATE UNIQUE INDEX "pairing_tokens_routing_id_key" ON "pairing_tokens" USING btree ("routing_id");--> statement-breakpoint
CREATE INDEX "pairing_tokens_account_created_idx" ON "pairing_tokens" USING btree ("account_id","created_at");--> statement-breakpoint
CREATE INDEX "pairings_account_idx" ON "pairings" USING btree ("account_id");--> statement-breakpoint
CREATE INDEX "pairings_agent_idx" ON "pairings" USING btree ("account_id","agent_device_id");--> statement-breakpoint
CREATE INDEX "pairings_client_idx" ON "pairings" USING btree ("account_id","client_device_id");--> statement-breakpoint
CREATE UNIQUE INDEX "push_tokens_device_key" ON "push_tokens" USING btree ("account_id","device_id");--> statement-breakpoint
CREATE POLICY "accounts_tenant_isolation" ON "accounts" AS PERMISSIVE FOR ALL TO "osprey_app" USING (id = nullif(current_setting('app.account_id', true), '')::uuid) WITH CHECK (id = nullif(current_setting('app.account_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "audit_relay_tenant_isolation" ON "audit_relay" AS PERMISSIVE FOR ALL TO "osprey_app" USING (account_id = nullif(current_setting('app.account_id', true), '')::uuid) WITH CHECK (account_id = nullif(current_setting('app.account_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "devices_tenant_isolation" ON "devices" AS PERMISSIVE FOR ALL TO "osprey_app" USING (account_id = nullif(current_setting('app.account_id', true), '')::uuid) WITH CHECK (account_id = nullif(current_setting('app.account_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "pairing_tokens_tenant_isolation" ON "pairing_tokens" AS PERMISSIVE FOR ALL TO "osprey_app" USING (account_id = nullif(current_setting('app.account_id', true), '')::uuid) WITH CHECK (account_id = nullif(current_setting('app.account_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "pairings_tenant_isolation" ON "pairings" AS PERMISSIVE FOR ALL TO "osprey_app" USING (account_id = nullif(current_setting('app.account_id', true), '')::uuid) WITH CHECK (account_id = nullif(current_setting('app.account_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "push_tokens_tenant_isolation" ON "push_tokens" AS PERMISSIVE FOR ALL TO "osprey_app" USING (account_id = nullif(current_setting('app.account_id', true), '')::uuid) WITH CHECK (account_id = nullif(current_setting('app.account_id', true), '')::uuid);--> statement-breakpoint
CREATE POLICY "quotas_tenant_isolation" ON "quotas" AS PERMISSIVE FOR ALL TO "osprey_app" USING (account_id = nullif(current_setting('app.account_id', true), '')::uuid) WITH CHECK (account_id = nullif(current_setting('app.account_id', true), '')::uuid);