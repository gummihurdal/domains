-- domains.azurenexus.com gallery: edit log (delete / restore / purge / rotate / caption / fav / unfav).
-- Each row is signed in the browser with an HMAC key derived from the gallery password; the page and the
-- Python sync (sync/sync_photos.py) ignore any row whose signature does not verify. Append-only for anon.
create table if not exists public.photo_edits (
  id bigint generated always as identity primary key,
  photo_id text not null check (char_length(photo_id) between 1 and 80),
  action text not null check (action in ('delete','restore','purge','rotate','caption','fav','unfav')),
  value text not null default '' check (char_length(value) <= 300),
  ts bigint not null,
  sig text not null unique check (char_length(sig) = 64),
  created_at timestamptz not null default now()
);
create index if not exists photo_edits_ts on public.photo_edits (ts);
alter table public.photo_edits enable row level security;
create policy "photo_edits read" on public.photo_edits for select to anon, authenticated using (true);
create policy "photo_edits append" on public.photo_edits for insert to anon, authenticated with check (true);
grant select, insert on public.photo_edits to anon, authenticated;
