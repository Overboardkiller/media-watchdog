<div align="center">
  <img src="https://raw.githubusercontent.com/overboardkiller/unraid-templates/main/icons/media-watchdog.svg" width="100" height="100" alt="Media Watchdog"/>
  <h1>Media Watchdog</h1>
  <p>Let your Emby users manage their own media — without giving them the keys to the kingdom.</p>

  ![Docker Pulls](https://img.shields.io/docker/pulls/overboardkiller/media-watchdog?style=flat-square&color=yellow)
  ![Docker Image Size](https://img.shields.io/docker/image-size/overboardkiller/media-watchdog/latest?style=flat-square&color=yellow)
  ![License](https://img.shields.io/github/license/overboardkiller/media-watchdog?style=flat-square&color=yellow)
  [![Ko-fi](https://img.shields.io/badge/support-ko--fi-FF5E5B?style=flat-square&logo=ko-fi&logoColor=white)](https://ko-fi.com/mediawatchdog)
</div>

---

## The problem it solves

Running an Emby server for family and friends with Seerr auto-approval works well — until people start requesting entire seasons of shows, watching two episodes, and moving on. Reality TV is another common one: downloaded, barely touched, sitting there forever.

Giving users delete access is too much. Manually monitoring every request is too time consuming. Media Watchdog fills that gap — it gives users a simple interface to review what they've requested and flag anything they no longer want. Admins get a dashboard showing everything across all users, with the ability to action those flags and delete directly from Radarr and Sonarr, or override a flag if something is worth keeping.

---

## What it does

- **Watch history at a glance** — cross-references Seerr requests with Emby watch history so you can see what's actually being watched, when it was last played, and how far through a series someone got
- **User flagging** — users log in with their Emby credentials and can flag their own requests for deletion, putting them in a queue for admin review
- **Admin controls** — admins see all requests across all users and can delete directly from Radarr and Sonarr, removing the file, the Seerr request, and the Arr entry in one action
- **Per-season management** — flag individual seasons of a show rather than the entire series, useful when someone is still watching later seasons
- **Protect from deletion** — admins can mark items as protected to prevent them being deleted even if a user flags them, handy when multiple people are watching the same content
- **Requester reassignment** — if media was downloaded for someone else under a different account, it can be reassigned so the correct user can manage it themselves (local to Media Watchdog only, does not affect Seerr)
- **TMDB scores** — displayed on every item so you can make informed decisions about what's worth keeping
- **Organised by Arr instance** — tabs reflect your actual Radarr and Sonarr instances with custom names you define
- **Scheduled cache refresh** — stays in sync with Seerr and Emby automatically

---

## Requirements

- Emby Server with API access enabled
- Seerr (Overseerr or Jellyseerr) with API access enabled
- Radarr and/or Sonarr *(optional — required for deletion features, must have file deletion rights enabled)*

---

## First time setup

On first launch, Media Watchdog will walk you through a three-step setup wizard:

1. **Emby** — enter your internal Emby URL and API key
2. **Seerr** — enter your internal Seerr URL and API key, and optionally your public Seerr URL for clickable links
3. **Admin account** — log in with your Emby admin account to complete setup

Once the wizard is complete, the app will run its first cache build automatically. After that:

- Go to **Settings → Sync from Seerr** — this imports all your Radarr and Sonarr instances directly from Seerr, including their URLs
- Add API keys for each Arr instance in Settings — this enables one-click deletion from the interface
- Radarr and Sonarr must have **file deletion enabled** in their settings for deletions to work end-to-end
- Deletion is restricted to **Emby admins only**

> **Note on requester reassignment:** If media was downloaded for another person and sits under the wrong account, it can be reassigned in Media Watchdog. This is a local override only — it does not modify anything in Seerr. Once reassigned, the correct user can flag it for deletion themselves.

---

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

---

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

---

## Volumes

| Path | Description |
|------|-------------|
| `/data` | Persistent storage for the database, session data, and logs. Must be mounted to survive container restarts. |
| `/emby-appdata` | Read-only mount of your Emby Server appdata directory. Used to read watch history directly from Emby's database. |

---

## Unraid

Available in Community Applications — search **Media Watchdog**.

Or add the template repository manually under **Apps → Settings → Template Repositories**:

```
https://github.com/overboardkiller/unraid-templates
```
