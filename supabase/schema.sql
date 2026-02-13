-- SafeCheck Supabase schema (minimal hackathon version)

create table if not exists public.scan_history (
  id uuid primary key default gen_random_uuid(),
  sha256 text not null,
  verdict text not null check (verdict in ('safe', 'suspicious', 'dangerous')),
  total_score numeric not null default 0,
  malicious_count integer not null default 0,
  suspicious_count integer not null default 0,
  harmless_count integer not null default 0,
  undetected_count integer not null default 0,
  source text not null default 'virustotal',
  created_at timestamptz not null default now()
);

create index if not exists scan_history_sha256_idx on public.scan_history (sha256);
create index if not exists scan_history_created_at_idx on public.scan_history (created_at desc);

-- Optional report queue table for later expansion
create table if not exists public.site_reports (
  id uuid primary key default gen_random_uuid(),
  domain text not null,
  notes text not null default '',
  status text not null default 'pending',
  created_by text,
  created_at timestamptz not null default now()
);

create index if not exists site_reports_domain_idx on public.site_reports (domain);
create index if not exists site_reports_created_at_idx on public.site_reports (created_at desc);
