<div align="center">
  <img src="https://raw.githubusercontent.com/overboardkiller/unraid-templates/main/icons/media-watchdog.svg" width="100" height="100" alt="Media Watchdog"/>
  <h1>Media Watchdog</h1>
  <p>Cross-reference your Seerr requests with your Emby watch history</p>

  ![Docker Pulls](https://img.shields.io/docker/pulls/overboardkiller/media-watchdog?style=flat-square&color=yellow)
  ![Docker Image Size](https://img.shields.io/docker/image-size/overboardkiller/media-watchdog/latest?style=flat-square&color=yellow)
  ![License](https://img.shields.io/github/license/overboardkiller/media-watchdog?style=flat-square&color=yellow)
</div>

---

I built this because I wanted a simple way to see what people were actually watching on my Emby server versus what was just sitting there taking up space. It pulls your request history from Seerr and matches it against Emby watch history, so you can see at a glance what's been watched, what hasn't, and who requested it.

## Features

- 🎬 &nbsp;Cross-reference Seerr requests with Emby watch history
- 👤 &nbsp;Users log in with their Emby credentials and see their own requests
- 🚩 &nbsp;Users can flag unwanted movies and shows for removal
- 🗑️ &nbsp;Admins can delete directly from Radarr or Sonarr with one click
- 📺 &nbsp;Per-season controls — flag individual seasons without touching the rest
- 📊 &nbsp;Watch progress bars and TMDB scores on every item
- 🛡️ &nbsp;Protect items from deletion
- ✏️ &nbsp;Reassign requesters
- 🗂️ &nbsp;Tabs organised by Arr instance with custom names and ordering
- 🔄 &nbsp;Scheduled cache rebuild keeps everything in sync automatically

## Requirements

- Emby Server
- Seerr (Overseerr or Jellyseerr)
- Radarr and/or Sonarr *(optional — required for deletion)*

## Setup

1. Open `http://your-server-ip:5000`
2. Run through the setup wizard — Emby details, Seerr details, then log in with your Emby admin account to complete setup
3. Go to **Settings → Sync from Seerr** to import your Radarr/Sonarr instances
4. Hit **Rebuild Cache** to populate the library

## Docker

```bash
docker run -d \
  --name media-watchdog \
  -p 5000:5000 \
  -v /path/to/appdata/media-watchdog/data:/data \
  -v /path/to/appdata/EmbyServer:/emby-appdata:ro \
  --restart unless-stopped \
  overboardkiller/media-watchdog:latest
```

## Docker Compose

```yaml
services:
  media-watchdog:
    image: overboardkiller/media-watchdog:latest
    container_name: media-watchdog
    restart: unless-stopped
    ports:
      - "5000:5000"
    volumes:
      - /path/to/appdata/media-watchdog/data:/data
      - /path/to/appdata/EmbyServer:/emby-appdata:ro
```

## Volumes

| Path | Description |
|------|-------------|
| `/data` | Database, logs, session data — must be persistent |
| `/emby-appdata` | Read-only path to your Emby Server appdata folder |

## Unraid

Available in Community Applications. Search **Media Watchdog** or add the template repo manually:

```
https://github.com/overboardkiller/unraid-templates
```
