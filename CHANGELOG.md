# Changelog

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
