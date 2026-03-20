-- AI Group PostgreSQL Test Data Seeding
-- Creates tables needed by AI/MCP tests
-- This is executed by setup-infras.bash as part of AI group infrastructure setup

CREATE TABLE IF NOT EXISTS public.tap_pgsql_static_accounts (
  account_id INT PRIMARY KEY,
  account_name TEXT NOT NULL UNIQUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS public.tap_pgsql_static_events (
  event_id INT PRIMARY KEY,
  account_id INT NOT NULL,
  event_type TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT fk_tap_pgsql_events_account
    FOREIGN KEY (account_id) REFERENCES public.tap_pgsql_static_accounts(account_id)
);

INSERT INTO public.tap_pgsql_static_accounts(account_id, account_name) VALUES
  (1, 'seed-pg-a'),
  (2, 'seed-pg-b')
ON CONFLICT (account_id) DO UPDATE SET account_name=EXCLUDED.account_name;

INSERT INTO public.tap_pgsql_static_events(event_id, account_id, event_type) VALUES
  (201, 1, 'signup'),
  (202, 2, 'purchase')
ON CONFLICT (event_id) DO UPDATE SET event_type=EXCLUDED.event_type;
