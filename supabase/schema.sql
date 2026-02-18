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

-- Source trust database used by URL checker
create table if not exists public.site_sources (
  domain text primary key,
  status text not null default 'unknown' check (status in ('legitimate', 'fake', 'unknown')),
  confidence text not null default 'medium' check (confidence in ('high', 'medium', 'low')),
  reports integer not null default 0,
  verified_by text not null default 'community',
  added_date timestamptz not null default now(),
  last_verified_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists site_sources_status_idx on public.site_sources (status);
create index if not exists site_sources_confidence_idx on public.site_sources (confidence);
create index if not exists site_sources_last_verified_idx on public.site_sources (last_verified_at desc);

-- Community report queue for moderation flow
create table if not exists public.site_reports (
  id uuid primary key default gen_random_uuid(),
  domain text not null,
  notes text not null default '',
  status text not null default 'pending' check (status in ('pending', 'pending_review', 'approved', 'rejected', 'needs_more_data')),
  created_by text,
  reviewed_by text,
  review_notes text,
  reviewed_at timestamptz,
  updated_at timestamptz not null default now(),
  created_at timestamptz not null default now()
);

create index if not exists site_reports_domain_idx on public.site_reports (domain);
create index if not exists site_reports_created_at_idx on public.site_reports (created_at desc);
create index if not exists site_reports_status_idx on public.site_reports (status);
