-- gallery: albums, people names and shared links (values encrypted by the page)
alter table public.photo_edits drop constraint if exists photo_edits_action_check;
alter table public.photo_edits add constraint photo_edits_action_check check (action in
  ('delete','restore','purge','rotate','caption','fav','unfav','album_add','album_remove','person','share','unshare'));
