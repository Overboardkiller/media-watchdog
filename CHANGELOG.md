# Changelog
## [v1.0.2] - 2026-07-02
### Fixed
- **Season data not loading** — `/api/seasons/<id>` now uses Emby's `AnyProviderIdEquals` filter to look up the show directly by TMDB/TVDB ID. Previously it fetched only one arbitrary series from the whole library (`Limit: 1`) and matched client-side, which almost always missed — season flags showed no episode counts or Emby data.
- **JSON corruption under concurrent writes, take two** — v1.0.1 introduced atomic writes via temp-file + `os.replace()`, but all workers shared one temp filename (`<file>.tmp`). With multiple gunicorn workers, two processes could still write to that same temp file at once, corrupting it before the rename. Temp filenames are now unique per process/thread (`<file>.<pid>.<tid>.tmp`), closing the race for good.
- **Lost writes under concurrent access** — all reads/writes to `watchdog.json` now go through a single locked transaction helper, so a flag/protect/config change can no longer be silently overwritten by a cache rebuild finishing at the same moment.
- **Login rate limiting bypassable via spoofed IP** — `X-Forwarded-For` is now only trusted when `TRUST_PROXY=1` is explicitly set, preventing trivial lockout bypass on deployments not sitting behind a trusted reverse proxy.
- Minor: unbounded pagination loop, dead code cleanup, deprecated `datetime.utcnow()`, bare `except:` clauses, expired sessions never pruned from `sessions.json`.
### Changed
- **Frontend is now fully self-hosted** — Tailwind CSS, Font Awesome, and Google Fonts (Inter, Space Grotesk) are vendored into `static/vendor/` instead of loaded from CDNs. The app now works fully offline and doesn't leak requests to third parties on every page load.
- Production server now runs via `waitress`/`gunicorn` rather than relying on Flask's development server fallback.
- Admins can now click the flag badge (🚩 username) directly to unflag an item, instead of only Delete/Keep.

---

## [v1.0.1] - 2026-07-02

### Fixed

- **Critical: JSON corruption on concurrent writes** — `save_data()`, `save_sessions()`, and `save_lockouts()` now write atomically using a temp file and `os.replace()`. Two gunicorn workers can no longer interleave writes and corrupt the database.

### Changed

- **Settings modal redesigned** — New left sidebar with three tabs: General, Arr Stack, and Logs. Activity log viewer moved inside Settings. Each Arr instance now has a manual URL input field. Cache interval updated to offer 1 hour, 12 hours, 1 day, and 1 week.

---

## [v1.0.0] - 2026-07-01

Initial public release.

- Emby auth-based login with role-based access (admin/user)
- Cross-reference Seerr requests with Emby watch history
- TMDB scores, series watch progress bars
- Flag items for deletion, admin review and delete from Radarr/Sonarr
- Per-season controls — flag individual seasons
- Admin Keep/Protect with shield badge
- Requester reassignment (local override)
- Arr instance tabs with custom names and ordering
- Scheduled cache rebuild
- Setup wizard
- Activity log
- Docker Hub: `overboardkiller/media-watchdog`
- Unraid Community Applications support
