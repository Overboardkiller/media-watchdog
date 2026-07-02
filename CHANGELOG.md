# Changelog

All notable changes to Media Watchdog will be documented here.

---

## [v1.0.0] - 2026-07-02

Initial public release.

### Features

**Core**
- Setup wizard (3-step: Emby → Seerr → admin login using Emby admin account)
- Emby credential login with brute force protection (5 attempts, 15 min lockout, persists across restarts)
- Role-based access — admin sees all requests, users see only their own
- Cross-reference Seerr requests with Emby watch history
- TMDB scores displayed on every item
- Series watch progress bars per user
- Cache auto-rebuild on startup and on a configurable schedule (1 hour / 12 hours / 1 day / 1 week)

**Tabs & Navigation**
- Tabs organised by Arr instance (Radarr, Sonarr etc) pulled from Seerr
- Custom tab names set per instance in Settings
- Drag to reorder tabs
- Tab order and names persist across cache rebuilds
- Type column shows Arr service name instead of generic Movie/Series
- Filters: All, Never Watched, Active, Flagged, Not in Emby
- Column visibility per tab — Radarr tabs hide Watch Progress, Sonarr tabs hide Last Watched

**Flagging & Deletion**
- Users can flag their own requests for deletion
- Admins review flags and delete directly from Radarr/Sonarr, Seerr, and Emby in one action
- Per-season flagging — flag individual seasons without affecting the whole series
- Delete confirmation modal shows exactly what will happen, including ✗ warnings when no Arr API key is set
- Protect items from deletion (admin only) with shield badge
- Orphaned requests (no TMDB data) shown as "Orphaned (TMDB: #)" instead of "Unknown"

**Admin Tools**
- Reassign requester — change who owns a request locally (does not affect Seerr)
- Reassignments persist across cache rebuilds
- Permissions — grant users visibility of other users' requests
- Activity log — full audit trail of logins, flags, deletions, cache builds, settings changes

**Settings**
- Tabbed settings modal: General, Arr Stack, Logs
- Emby and Seerr URL + API key configuration
- Seerr public URL for clickable links
- Arr instances: sync from Seerr, manual URL entry, API key per instance, drag reorder, custom names
- All API keys masked with 28 bullets when saved
- Cache interval configurable

**Infrastructure**
- Docker image: `overboardkiller/media-watchdog`
- Available in Unraid Community Applications
- Gunicorn production server (2 workers, 4 threads)
- Encrypted config at rest (Fernet)
- Persistent sessions across restarts

### Known Limitations
- Seerr does not expose internal Arr URLs via API — must be entered manually in Settings → Arr Stack
- Items requested before Seerr tracked serviceId will appear under the default Arr instance tab
- Orphaned requests (deleted from TMDB) cannot have titles recovered

---
