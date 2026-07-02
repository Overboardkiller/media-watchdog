from flask import Flask, request, jsonify, send_from_directory
import json, os, requests as req_lib, secrets, time, threading, shutil, copy
from functools import wraps
from contextlib import contextmanager
from datetime import datetime, timezone
from cryptography.fernet import Fernet
import base64, hashlib

app = Flask(__name__, static_folder='static')
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024  # 1MB request limit

DATA_FILE     = '/data/watchdog.json'
SESSION_FILE  = '/data/sessions.json'
LOCKOUT_FILE  = '/data/lockouts.json'
LOG_FILE      = '/data/watchdog.log'
EMBY_APPDATA  = '/emby-appdata'

# ── Encryption ────────────────────────────────────────────────────────────────
def get_secret_key():
    env_key = os.environ.get('SECRET_KEY', '').strip()
    if env_key:
        return env_key
    secret_path = '/data/.secret'
    if os.path.exists(secret_path):
        with open(secret_path) as f:
            return f.read().strip()
    key = secrets.token_hex(32)
    os.makedirs('/data', exist_ok=True)
    with open(secret_path, 'w') as f:
        f.write(key)
    return key

def _fernet():
    raw = get_secret_key().encode()
    derived = base64.urlsafe_b64encode(hashlib.sha256(raw).digest())
    return Fernet(derived)

def encrypt_value(val):
    if not val:
        return ''
    return _fernet().encrypt(val.encode()).decode()

def decrypt_value(val):
    if not val:
        return ''
    try:
        return _fernet().decrypt(val.encode()).decode()
    except Exception:
        return val

ENCRYPTED_FIELDS = {'emby_key', 'overseerr_key'}

def encrypt_config(cfg):
    out = dict(cfg)
    for field in ENCRYPTED_FIELDS:
        if field in out and out[field]:
            out[field] = encrypt_value(out[field])
    return out

def decrypt_config(cfg):
    out = dict(cfg)
    for field in ENCRYPTED_FIELDS:
        if field in out and out[field]:
            out[field] = decrypt_value(out[field])
    return out

def mask_config(cfg):
    out = dict(cfg)
    for field in ENCRYPTED_FIELDS:
        if out.get(field):
            out[field] = '••••••••'
    return out

# ── Activity log ──────────────────────────────────────────────────────────────
_log_lock = threading.Lock()

def write_log(event_type, detail, username=None, ip=None):
    entry = {
        'ts':       time.time(),
        'dt':       datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC'),
        'type':     event_type,
        'detail':   detail,
        'username': username,
        'ip':       ip
    }
    with _log_lock:
        os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps(entry) + '\n')

def read_log(limit=200):
    if not os.path.exists(LOG_FILE):
        return []
    try:
        with open(LOG_FILE) as f:
            lines = f.readlines()
        entries = []
        for line in lines:
            try:
                entries.append(json.loads(line.strip()))
            except Exception:
                pass
        return list(reversed(entries[-limit:]))
    except Exception:
        return []

# ── Login rate limiting (persistent) ─────────────────────────────────────────
_lockout_lock = threading.Lock()
MAX_ATTEMPTS    = 5
WINDOW_SECONDS  = 300
LOCKOUT_SECONDS = 900

def load_lockouts():
    if not os.path.exists(LOCKOUT_FILE):
        return {}
    try:
        with open(LOCKOUT_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

# Atomic JSON write — prevents readers ever seeing a half-written file
def atomic_write_json(path, obj, **dump_kwargs):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f"{path}.tmp"
    with open(tmp, 'w') as f:
        json.dump(obj, f, **dump_kwargs)
    os.replace(tmp, path)

def save_lockouts(data):
    atomic_write_json(LOCKOUT_FILE, data)

# Only trust X-Forwarded-For when explicitly running behind a reverse proxy
# (set TRUST_PROXY=1). Otherwise a client could spoof the header and bypass
# login rate limiting entirely.
TRUST_PROXY = os.environ.get('TRUST_PROXY', '').strip().lower() in ('1', 'true', 'yes')

def get_client_ip():
    if TRUST_PROXY:
        xff = request.headers.get('X-Forwarded-For', '')
        if xff:
            return xff.split(',')[0].strip()
    return request.remote_addr or 'unknown'

def is_rate_limited(ip):
    with _lockout_lock:
        now = time.time()
        lockouts = load_lockouts()
        attempts = lockouts.get(ip, [])
        attempts = [t for t in attempts if now - t < LOCKOUT_SECONDS]
        lockouts[ip] = attempts
        save_lockouts(lockouts)
        recent = [t for t in attempts if now - t < WINDOW_SECONDS]
        if len(recent) >= MAX_ATTEMPTS:
            oldest = min(recent)
            retry_after = int(LOCKOUT_SECONDS - (now - oldest))
            return True, max(retry_after, 1)
        return False, 0

def record_failed_login(ip):
    with _lockout_lock:
        lockouts = load_lockouts()
        lockouts.setdefault(ip, []).append(time.time())
        save_lockouts(lockouts)

def clear_login_attempts(ip):
    with _lockout_lock:
        lockouts = load_lockouts()
        lockouts.pop(ip, None)
        save_lockouts(lockouts)

# ── Setup rate limiting ───────────────────────────────────────────────────────
_setup_attempts = {}
_setup_lock = threading.Lock()

def is_setup_rate_limited(ip):
    with _setup_lock:
        now = time.time()
        attempts = [t for t in _setup_attempts.get(ip, []) if now - t < 3600]
        _setup_attempts[ip] = attempts
        if len(attempts) >= 3:
            return True
        attempts.append(now)
        _setup_attempts[ip] = attempts
        return False

# ── Data helpers ──────────────────────────────────────────────────────────────
# Guards every load→mutate→save cycle on watchdog.json. Without this, the
# cache-builder thread and request handlers can interleave and silently drop
# writes (e.g. a flag set while a cache build is finishing).
_data_lock = threading.RLock()

def load_data():
    if not os.path.exists(DATA_FILE):
        return {
            'setup_complete': False,
            'config': {'cache_interval_hours': 24},
            'admin_emby_id': None,
            'admin_username': None,
            'permissions': {},
            'flags': {},
            'protected': {},
            'cache': {'built_at': None, 'results': [], 'libraries': []}
        }
    with open(DATA_FILE) as f:
        d = json.load(f)
    if 'cache' not in d:
        d['cache'] = {'built_at': None, 'results': [], 'libraries': []}
    if 'libraries' not in d['cache']:
        d['cache']['libraries'] = []
    if 'cache_interval_hours' not in d.get('config', {}):
        d['config']['cache_interval_hours'] = 24
    if 'overseerr_public_url' not in d.get('config', {}):
        d['config']['overseerr_public_url'] = ''
    # Clear overseerr_public_url if it was accidentally stored as an encrypted string
    pub = d['config'].get('overseerr_public_url', '')
    if isinstance(pub, str) and pub.startswith('gAAAAA'):
        d['config']['overseerr_public_url'] = ''
    if 'protected' not in d:
        d['protected'] = {}
    if 'season_flags' not in d:
        d['season_flags'] = {}
    if 'requester_overrides' not in d:
        d['requester_overrides'] = {}
    return d

def save_data(data):
    atomic_write_json(DATA_FILE, data, indent=2)

@contextmanager
def data_transaction():
    """Locked read-modify-write on watchdog.json. Saves on clean exit."""
    with _data_lock:
        data = load_data()
        yield data
        save_data(data)

# ── Session helpers ───────────────────────────────────────────────────────────
_session_lock  = threading.RLock()
SESSION_MAX_AGE = 86400 * 7

def load_sessions():
    if not os.path.exists(SESSION_FILE):
        return {}
    try:
        with open(SESSION_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_sessions(sessions):
    # Prune expired sessions so the file doesn't grow forever
    now = time.time()
    live = {t: s for t, s in sessions.items()
            if now - s.get('created_at', 0) <= SESSION_MAX_AGE}
    atomic_write_json(SESSION_FILE, live)

def make_token():
    return secrets.token_hex(32)

def get_session(token):
    if not token:
        return None
    with _session_lock:
        sessions = load_sessions()
        s = sessions.get(token)
        if not s:
            return None
        if time.time() - s['created_at'] > SESSION_MAX_AGE:
            sessions.pop(token, None)
            save_sessions(sessions)
            return None
        return s

def create_session(user_id, username, is_admin):
    token = make_token()
    with _session_lock:
        sessions = load_sessions()
        sessions[token] = {
            'emby_user_id': user_id, 'username': username,
            'is_admin': is_admin, 'created_at': time.time()
        }
        save_sessions(sessions)
    return token

def destroy_session(token):
    with _session_lock:
        sessions = load_sessions()
        sessions.pop(token, None)
        save_sessions(sessions)

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Token')
        session = get_session(token)
        if not session:
            return jsonify({'error': 'Unauthorised'}), 401
        request.session = session
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('X-Token')
        session = get_session(token)
        if not session:
            return jsonify({'error': 'Unauthorised'}), 401
        if not session.get('is_admin'):
            return jsonify({'error': 'Admin required'}), 403
        request.session = session
        return f(*args, **kwargs)
    return decorated

# ── Emby helpers ──────────────────────────────────────────────────────────────
def emby_authenticate(emby_url, emby_key, username, password):
    try:
        resp = req_lib.post(
            f"{emby_url.rstrip('/')}/Users/AuthenticateByName",
            json={"Username": username, "Pw": password},
            headers={
                "X-Emby-Authorization": f'MediaBrowser Client="MediaWatchdog", Device="Server", DeviceId="watchdog", Version="1.0", Token="{emby_key}"',
                "Content-Type": "application/json"
            },
            timeout=10
        )
        return resp.json() if resp.status_code == 200 else None
    except Exception as e:
        print(f"Emby auth error: {e}")
        return None

def emby_get_users(emby_url, emby_key):
    try:
        resp = req_lib.get(f"{emby_url.rstrip('/')}/Users", params={"api_key": emby_key}, timeout=10)
        return resp.json() if resp.status_code == 200 else []
    except Exception:
        return []

def emby_get_libraries(emby_url, emby_key):
    try:
        resp = req_lib.get(
            f"{emby_url.rstrip('/')}/Library/VirtualFolders",
            params={"api_key": emby_key},
            timeout=10
        )
        if resp.status_code == 200:
            return [{'id': lib.get('ItemId',''), 'name': lib.get('Name',''), 'type': lib.get('CollectionType','')} for lib in resp.json()]
    except Exception:
        pass
    return []

def overseerr_get(url, key, path):
    resp = req_lib.get(f"{url.rstrip('/')}{path}", headers={"X-Api-Key": key}, timeout=15)
    resp.raise_for_status()
    return resp.json()

def fetch_all_requests(overseerr_url, overseerr_key):
    results, page = [], 1
    while True:
        data = overseerr_get(overseerr_url, overseerr_key,
                             f"/api/v1/request?take=100&skip={(page-1)*100}&sort=added&filter=all")
        batch = data.get('results', [])
        results.extend(batch)
        # Guard: if a page comes back empty, stop — pageInfo.results can
        # overstate the total (e.g. requests deleted mid-pagination), which
        # would otherwise loop forever.
        if not batch:
            break
        if len(results) >= data.get('pageInfo', {}).get('results', 0):
            break
        page += 1
    return results

def fetch_seerr_services(overseerr_url, overseerr_key):
    """Fetch all configured Radarr and Sonarr instances from Seerr."""
    services = []
    for stype in ('radarr', 'sonarr'):
        try:
            resp = req_lib.get(
                f"{overseerr_url.rstrip('/')}/api/v1/service/{stype}",
                headers={"X-Api-Key": overseerr_key},
                timeout=10
            )
            if resp.status_code == 200:
                for svc in resp.json():
                    composite_id = f"{stype}:{svc.get('id', '')}"
                    services.append({
                        'seerr_service_id': composite_id,
                        'name':             svc.get('name', ''),
                        'type':             stype,
                        'url':              _build_arr_url(svc),
                        'is4k':             svc.get('is4k', False)
                    })
        except Exception as e:
            print(f"[cache] Could not fetch Seerr {stype} services: {e}")
    return services

def _build_arr_url(svc):
    """Build URL from Seerr service object."""
    hostname = svc.get('hostname') or svc.get('externalUrl') or ''
    port     = svc.get('port', '')
    ssl      = svc.get('useSsl', False)
    if hostname:
        scheme = 'https' if ssl else 'http'
        return f"{scheme}://{hostname}:{port}" if port else f"{scheme}://{hostname}"
    return ''

# ── Playback Reporting DB ─────────────────────────────────────────────────────
def get_playback_db_path():
    candidates = [
        os.path.join(EMBY_APPDATA, 'data', 'playback_reporting.db'),
        os.path.join(EMBY_APPDATA, 'config', 'data', 'playback_reporting.db'),
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    try:
        for root, dirs, files in os.walk(EMBY_APPDATA):
            for f in files:
                if f == 'playback_reporting.db':
                    return os.path.join(root, f)
            dirs[:] = [d for d in dirs if root == EMBY_APPDATA]
    except Exception:
        pass
    return None

def get_series_episodes(emby_url, emby_key, series_id):
    try:
        resp = req_lib.get(
            f"{emby_url.rstrip('/')}/Items",
            params={'ParentId': series_id, 'Recursive': 'true',
                    'IncludeItemTypes': 'Episode', 'Fields': 'Id',
                    'Limit': 2000, 'api_key': emby_key},
            timeout=15
        )
        if resp.status_code == 200:
            items = resp.json().get('Items', [])
            return len(items), [item['Id'] for item in items]
    except Exception:
        pass
    return 0, []

# ── Cache builder ─────────────────────────────────────────────────────────────
_cache_lock     = threading.Lock()
_cache_building = False

def build_cache():
    global _cache_building
    with _cache_lock:
        if _cache_building:
            return
        _cache_building = True

    write_log('cache', 'Cache build started')
    print(f"[cache] Starting cache build at {datetime.now().isoformat()}")
    try:
        data = load_data()
        cfg  = decrypt_config(data['config'])

        emby_users = emby_get_users(cfg['emby_url'], cfg['emby_key'])
        user_map   = {u['Id']: u['Name'] for u in emby_users}

        libraries = emby_get_libraries(cfg['emby_url'], cfg['emby_key'])

        lib_item_sets = {}
        for lib in libraries:
            try:
                resp = req_lib.get(
                    f"{cfg['emby_url']}/Items",
                    params={'ParentId': lib['id'], 'Recursive': 'true',
                            'IncludeItemTypes': 'Movie,Series', 'Fields': 'ProviderIds',
                            'Limit': 5000, 'api_key': cfg['emby_key']},
                    timeout=30
                )
                if resp.status_code == 200:
                    lib_item_sets[lib['name']] = {item['Id'] for item in resp.json().get('Items', [])}
            except Exception:
                lib_item_sets[lib['name']] = set()

        requests_list = fetch_all_requests(cfg['overseerr_url'], cfg['overseerr_key'])
        print(f"[cache] Fetched {len(requests_list)} requests")

        # Fetch Seerr's configured Arr services for tab grouping
        seerr_services = fetch_seerr_services(cfg['overseerr_url'], cfg['overseerr_key'])
        print(f"[cache] Found {len(seerr_services)} Seerr Arr services")

        seen = {}
        for r in requests_list:
            media = r.get('media', {})
            key   = (r.get('type'), str(media.get('tmdbId', '')))
            existing = seen.get(key)
            if not existing or r.get('id', 0) > existing.get('id', 0):
                seen[key] = r
        requests_list = list(seen.values())

        emby_items = []
        for attempt in range(3):
            try:
                er = req_lib.get(
                    f"{cfg['emby_url']}/Items",
                    params={'Recursive': 'true', 'IncludeItemTypes': 'Movie,Series',
                            'Fields': 'Name,ProviderIds', 'Limit': 10000, 'api_key': cfg['emby_key']},
                    timeout=120
                )
                emby_items = er.json().get('Items', [])
                if emby_items:
                    break
            except Exception as e:
                print(f"[cache] ERROR fetching Emby library (attempt {attempt+1}): {e}")
                time.sleep(5)

        tmdb_map, tvdb_map = {}, {}
        for item in emby_items:
            p = item.get('ProviderIds', {})
            for k in ('Tmdb', 'tmdb'):
                if p.get(k): tmdb_map[str(p[k])] = item
            for k in ('Tvdb', 'tvdb'):
                if p.get(k): tvdb_map[str(p[k])] = item

        title_cache = {}
        for r in requests_list:
            mt  = r.get('type', 'movie')
            tid = r.get('media', {}).get('tmdbId')
            if not tid or (mt, tid) in title_cache:
                continue
            # Pre-populate fallback title from Seerr media object (available without TMDB)
            seerr_media_obj = next((r2.get('media',{}) for r2 in requests_list
                                    if r2.get('media',{}).get('tmdbId') == tid
                                    and r2.get('type','') == mt), {})
            seerr_fallback = (seerr_media_obj.get('title') or
                              seerr_media_obj.get('originalTitle') or
                              seerr_media_obj.get('name') or
                              seerr_media_obj.get('originalName') or '')
            try:
                endpoint = f"/api/v1/{'movie' if mt == 'movie' else 'tv'}/{tid}"
                detail   = overseerr_get(cfg['overseerr_url'], cfg['overseerr_key'], endpoint)
                t     = detail.get('title') or detail.get('name') or detail.get('originalTitle') or detail.get('originalName') or seerr_fallback or 'Unknown'
                y     = (detail.get('releaseDate') or detail.get('firstAirDate') or '')[:4]
                score = detail.get('voteAverage')
                title_cache[(mt, tid)] = {'title': t, 'year': y, 'score': score}
            except Exception:
                # Fall back to Seerr media title if TMDB lookup fails — avoid 'Unknown' if possible
                fallback_title = seerr_fallback if seerr_fallback and seerr_fallback.lower() != 'unknown' else 'Unknown'
                title_cache[(mt, tid)] = {'title': fallback_title, 'year': '', 'score': None}

        threshold_seconds = 3 * 30 * 24 * 60 * 60
        now          = time.time()

        results = []
        for r in requests_list:
            requester_name    = (r.get('requestedBy') or {}).get('displayName') or \
                                (r.get('requestedBy') or {}).get('username') or 'Unknown'
            requester_emby_id = next((uid for uid, uname in user_map.items()
                                      if uname.lower() == requester_name.lower()), None)

            media     = r.get('media', {})
            tmdb_id   = str(media.get('tmdbId', ''))
            tvdb_id   = str(media.get('tvdbId', ''))
            mtype_key = r.get('type', 'movie')
            mtype     = 'Movie' if mtype_key == 'movie' else 'Series'
            req_id    = str(r.get('id', ''))
            cached    = title_cache.get((mtype_key, media.get('tmdbId')), {})
            title     = cached.get('title', 'Unknown')
            year      = cached.get('year', '')
            score     = cached.get('score')

            emby_item   = tmdb_map.get(tmdb_id) or tvdb_map.get(tvdb_id)
            last_played = None
            total_plays = 0
            watchers    = []
            user_watch_pcts = {}
            total_episodes  = 0

            item_library = None
            if emby_item:
                for lib_name, lib_ids in lib_item_sets.items():
                    if emby_item['Id'] in lib_ids:
                        item_library = lib_name
                        break

            if emby_item:
                item_id = emby_item['Id']
                if mtype == 'Series':
                    total_episodes, _ = get_series_episodes(cfg['emby_url'], cfg['emby_key'], item_id)

                for user in emby_users:
                    uid   = user['Id']
                    uname = user_map.get(uid, uid)
                    try:
                        if mtype == 'Series' and total_episodes > 0:
                            played_resp = req_lib.get(
                                f"{cfg['emby_url']}/Users/{uid}/Items",
                                params={'ParentId': item_id, 'Recursive': 'true',
                                        'IncludeItemTypes': 'Episode', 'Filters': 'IsPlayed',
                                        'Fields': 'UserData', 'Limit': 2000, 'api_key': cfg['emby_key']},
                                timeout=12
                            )
                            if played_resp.status_code == 200:
                                pdata = played_resp.json()
                                played_count = pdata.get('TotalRecordCount', 0)
                                if played_count > 0:
                                    pct = min(100, round((played_count / total_episodes) * 100))
                                    user_watch_pcts[uname] = pct
                                    total_plays += played_count
                                    if uname not in watchers:
                                        watchers.append(uname)
                                    for ep in pdata.get('Items', []):
                                        lpd = ep.get('UserData', {}).get('LastPlayedDate')
                                        if lpd:
                                            d = datetime.fromisoformat(lpd.replace('Z', '+00:00'))
                                            ts = d.timestamp()
                                            if last_played is None or ts > last_played:
                                                last_played = ts
                        else:
                            ud_resp = req_lib.get(
                                f"{cfg['emby_url']}/Users/{uid}/Items/{item_id}",
                                params={'Fields': 'UserData', 'api_key': cfg['emby_key']},
                                timeout=8
                            )
                            if ud_resp.status_code == 200:
                                ud    = ud_resp.json().get('UserData', {})
                                plays = ud.get('PlayCount', 0)
                                is_played = ud.get('Played', False)
                                if plays > 0 or is_played:
                                    total_plays += max(plays, 1)
                                    if uname not in watchers:
                                        watchers.append(uname)
                                    lpd = ud.get('LastPlayedDate')
                                    if lpd:
                                        d  = datetime.fromisoformat(lpd.replace('Z', '+00:00'))
                                        ts = d.timestamp()
                                        if last_played is None or ts > last_played:
                                            last_played = ts
                    except Exception as e:
                        print(f"[cache] Error fetching user data for {uname}/{title}: {e}")

            any_watched = total_plays > 0 or any(p > 0 for p in user_watch_pcts.values())

            if not emby_item:
                status = 'notemby'
            elif not any_watched:
                status = 'unwatched'
            elif last_played and (now - last_played) > threshold_seconds:
                status = 'stale'
            else:
                status = 'active'

            flag      = data['flags'].get(req_id)
            protected = data['protected'].get(req_id)
            season_flags = data.get('season_flags', {}).get(req_id, [])
            os_path   = 'movie' if mtype_key == 'movie' else 'tv'
            link_base = cfg.get('overseerr_public_url','').rstrip('/') or cfg['overseerr_url'].rstrip('/')

            # Extract serviceId from Seerr request — build composite type:id key
            seerr_media     = r.get('media', {})
            svc_id          = str(seerr_media.get('serviceId', '') or '')
            svc_id_4k       = str(seerr_media.get('serviceId4k', '') or '')
            raw_svc_id      = svc_id_4k if svc_id_4k and svc_id_4k != '-1' else svc_id
            arr_type        = 'radarr' if mtype_key == 'movie' else 'sonarr'
            service_id      = f"{arr_type}:{raw_svc_id}" if raw_svc_id and raw_svc_id != '' else ''

            results.append({
                'req_id':            req_id,
                'title':             title,
                'year':              year,
                'type':              mtype,
                'library':           item_library,
                'service_id':        service_id,
                'tvdb_id':           tvdb_id,
                'tmdb_id':           tmdb_id,
                'score':             round(score, 1) if score is not None else None,
                'requested_by':      requester_name,
                'requester_emby_id': requester_emby_id,
                'requested_at':      r.get('createdAt'),
                'status':            status,
                'last_played':       last_played,
                'total_plays':       total_plays,
                'watchers':          watchers,
                'user_watch_pcts':   user_watch_pcts,
                'total_episodes':    total_episodes,
                'flagged':           bool(flag),
                'flag_note':         flag.get('note', '') if flag else '',
                'flag_by':           flag.get('flagged_by', '') if flag else '',
                'protected':         bool(protected),
                'protected_by':      protected.get('protected_by', '') if protected else '',
                'season_flags':      season_flags,
                'overseerr_link':    f"{link_base}/{os_path}/{tmdb_id}"
            })

        # Final merge under the data lock: everything above was slow network
        # work against a snapshot; re-load fresh data here so flags/protections
        # set during the build are neither lost nor stale in the cache.
        with data_transaction() as data:
            # Refresh flag/protect/season annotations from fresh data
            for r in results:
                rid       = r['req_id']
                flag      = data['flags'].get(rid)
                protected = data['protected'].get(rid)
                r['flagged']      = bool(flag)
                r['flag_note']    = flag.get('note', '') if flag else ''
                r['flag_by']      = flag.get('flagged_by', '') if flag else ''
                r['protected']    = bool(protected)
                r['protected_by'] = protected.get('protected_by', '') if protected else ''
                r['season_flags'] = data.get('season_flags', {}).get(rid, [])

            # Merge custom_name from configured arr_instances into seerr_services
            # Support both composite keys (radarr:0) and old-style bare IDs (0) during migration
            inst_map = {}
            for i in data['config'].get('arr_instances', []):
                sid = i.get('seerr_service_id', '')
                inst_map[sid] = i
                itype = i.get('type', '')
                if itype and sid and ':' not in sid:
                    inst_map[f"{itype}:{sid}"] = i
            for svc in seerr_services:
                inst = inst_map.get(svc['seerr_service_id'], {})
                svc['custom_name'] = inst.get('custom_name', '')

            # Re-sort seerr_services to match arr_instances order (preserves user-defined tab order)
            # Build composite ID lookup for old-style bare IDs
            arr_order_composite = []
            for i in data['config'].get('arr_instances', []):
                sid = i.get('seerr_service_id', '')
                itype = i.get('type', '')
                if ':' not in sid and itype:
                    arr_order_composite.append(f"{itype}:{sid}")
                else:
                    arr_order_composite.append(sid)
            if arr_order_composite:
                def sort_key(svc):
                    sid = svc.get('seerr_service_id', '')
                    try:
                        return arr_order_composite.index(sid)
                    except ValueError:
                        return len(arr_order_composite)  # new instances go to end
                seerr_services.sort(key=sort_key)

            # Apply any persisted requester overrides on top of fresh results
            overrides = data.get('requester_overrides', {})
            for r in results:
                if r['req_id'] in overrides:
                    ov = overrides[r['req_id']]
                    r['requested_by']      = ov.get('username', r['requested_by'])
                    r['requester_emby_id'] = ov.get('emby_id', r.get('requester_emby_id'))

            data['cache'] = {
                'built_at':       time.time(),
                'results':        results,
                'libraries':      [l['name'] for l in libraries],
                'seerr_services': seerr_services
            }
        write_log('cache', f'Cache build complete — {len(results)} items, {len(seerr_services)} Arr services')
        print(f"[cache] Cache built — {len(results)} items")

    except Exception as e:
        write_log('cache', f'Cache build FAILED: {e}')
        print(f"[cache] Build failed: {e}")
        import traceback; traceback.print_exc()
    finally:
        _cache_building = False

def build_cache_async():
    threading.Thread(target=build_cache, daemon=True).start()

# ── Background scheduler ──────────────────────────────────────────────────────
def cache_scheduler():
    first_run = True
    while True:
        data = load_data()
        if not data['setup_complete']:
            time.sleep(60)
            continue
        interval_hours = data['config'].get('cache_interval_hours', 24)
        built_at       = data['cache'].get('built_at')
        age_hours      = (time.time() - built_at) / 3600 if built_at else 999
        # Always rebuild on first run after container start, or when interval elapsed
        if first_run or age_hours >= interval_hours:
            first_run = False
            build_cache()
        time.sleep(300)

threading.Thread(target=cache_scheduler, daemon=True).start()

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/api/status')
def status():
    data = load_data()
    return jsonify({'setup_complete': data['setup_complete']})

@app.route('/api/setup', methods=['POST'])
def setup():
    ip = get_client_ip()
    if is_setup_rate_limited(ip):
        write_log('setup', 'Setup rate limited', ip=ip)
        return jsonify({'error': 'Too many setup attempts. Try again later.'}), 429

    data = load_data()
    if data['setup_complete']:
        return jsonify({'error': 'Already set up'}), 400

    body          = request.json or {}
    emby_url      = body.get('emby_url', '').rstrip('/')
    emby_key      = body.get('emby_key', '')
    overseerr_url = body.get('overseerr_url', '').rstrip('/')
    overseerr_key = body.get('overseerr_key', '')

    if not all([emby_url, emby_key, overseerr_url, overseerr_key]):
        return jsonify({'error': 'All fields required'}), 400

    auth = emby_authenticate(emby_url, emby_key, body.get('username',''), body.get('password',''))
    if not auth:
        return jsonify({'error': 'Emby authentication failed — check credentials'}), 401
    try:
        overseerr_get(overseerr_url, overseerr_key, '/api/v1/settings/main')
    except Exception as e:
        return jsonify({'error': f'Overseerr connection failed: {e}'}), 400

    user = auth.get('User', {})

    with data_transaction() as data:
        if data['setup_complete']:
            return jsonify({'error': 'Already set up'}), 400
        data['setup_complete'] = True
        data['config'] = encrypt_config({
            'emby_url': emby_url,
            'emby_key': emby_key,
            'overseerr_url': overseerr_url,
            'overseerr_key': overseerr_key,
            'overseerr_public_url': '',
            'cache_interval_hours': 24
        })
        data['admin_emby_id']  = user['Id']
        data['admin_username'] = user['Name']

    token = create_session(user['Id'], user['Name'], True)

    write_log('setup', f'Initial setup completed by {user["Name"]}', username=user['Name'], ip=ip)
    build_cache_async()
    return jsonify({'token': token, 'username': user['Name'], 'is_admin': True})

@app.route('/api/login', methods=['POST'])
def login():
    data = load_data()
    if not data['setup_complete']:
        return jsonify({'error': 'Not set up yet'}), 400

    ip = get_client_ip()
    limited, retry_after = is_rate_limited(ip)
    if limited:
        mins = (retry_after + 59) // 60
        write_log('login', f'Login blocked — rate limited', ip=ip)
        return jsonify({'error': f'Too many failed attempts. Try again in {mins} minute(s).'}), 429

    body = request.json or {}
    cfg  = decrypt_config(data['config'])
    auth = emby_authenticate(cfg['emby_url'], cfg['emby_key'],
                              body.get('username',''), body.get('password',''))
    if not auth:
        record_failed_login(ip)
        write_log('login', f'Failed login attempt for "{body.get("username","")}"', ip=ip)
        return jsonify({'error': 'Invalid username or password'}), 401

    clear_login_attempts(ip)
    user     = auth.get('User', {})
    is_admin = user['Id'] == data['admin_emby_id']
    token    = create_session(user['Id'], user['Name'], is_admin)

    write_log('login', f'Successful login{"  [admin]" if is_admin else ""}', username=user['Name'], ip=ip)
    return jsonify({'token': token, 'username': user['Name'], 'is_admin': is_admin})

@app.route('/api/logout', methods=['POST'])
@require_auth
def logout():
    token = request.headers.get('X-Token')
    username = request.session.get('username')
    destroy_session(token)
    write_log('login', 'Logged out', username=username, ip=get_client_ip())
    return jsonify({'ok': True})

@app.route('/api/report')
@require_auth
def report():
    data     = load_data()
    me       = request.session
    cache    = data.get('cache', {})
    built_at = cache.get('built_at')
    results  = cache.get('results', [])
    libraries= cache.get('libraries', [])

    seerr_services = copy.deepcopy(cache.get('seerr_services', []))
    # Annotate seerr_services with has_arr_key so frontend can show delete confirmation correctly
    cfg = decrypt_config(data.get('config', {}))
    decrypted_instances = get_arr_instances(cfg)
    inst_key_map = {}
    for inst in decrypted_instances:
        sid = inst.get('seerr_service_id', '')
        itype = inst.get('type', '')
        inst_key_map[sid] = bool(inst.get('key', ''))
        if ':' not in sid and itype:
            inst_key_map[f"{itype}:{sid}"] = bool(inst.get('key', ''))
    for svc in seerr_services:
        svc['has_arr_key'] = inst_key_map.get(svc.get('seerr_service_id', ''), False)

    # Include masked arr_instances so frontend can derive tab order/names from single source
    masked_instances = mask_arr_instances(data['config'].get('arr_instances', []))

    if not results and not _cache_building:
        build_cache_async()
        return jsonify({'building': True, 'results': [], 'libraries': [],
                        'seerr_services': seerr_services,
                        'arr_instances': masked_instances,
                        'is_admin': me['is_admin'], 'username': me['username'],
                        'built_at': None, 'cache_interval_hours': data['config'].get('cache_interval_hours', 24)})

    if _cache_building:
        return jsonify({'building': True, 'results': results, 'libraries': libraries,
                        'seerr_services': seerr_services,
                        'arr_instances': masked_instances,
                        'is_admin': me['is_admin'], 'username': me['username'],
                        'built_at': built_at, 'cache_interval_hours': data['config'].get('cache_interval_hours', 24)})

    visible_ids = None
    if not me['is_admin']:
        granted     = data['permissions'].get(me['emby_user_id'], [])
        visible_ids = set([me['emby_user_id']] + granted)

    filtered = []
    for r in results:
        if visible_ids is not None and r.get('requester_emby_id') not in visible_ids:
            continue
        flag      = data['flags'].get(r['req_id'])
        protected = data['protected'].get(r['req_id'])
        r2 = dict(r)
        r2['flagged']      = bool(flag)
        r2['flag_note']    = flag.get('note', '') if flag else ''
        r2['flag_by']      = flag.get('flagged_by', '') if flag else ''
        r2['protected']    = bool(protected)
        r2['protected_by'] = protected.get('protected_by', '') if protected else ''
        if not me['is_admin']:
            own_pct = r2.get('user_watch_pcts', {}).get(me['username'])
            r2['user_watch_pcts'] = {me['username']: own_pct} if own_pct is not None else {}
        filtered.append(r2)

    return jsonify({'building': False, 'results': filtered, 'libraries': libraries,
                    'seerr_services': seerr_services,
                    'arr_instances': masked_instances,
                    'is_admin': me['is_admin'], 'username': me['username'],
                    'built_at': built_at, 'cache_interval_hours': data['config'].get('cache_interval_hours', 24)})

@app.route('/api/refresh', methods=['POST'])
@require_admin
def force_refresh():
    if _cache_building:
        return jsonify({'ok': False, 'message': 'Already building'})
    write_log('cache', 'Manual cache rebuild triggered', username=request.session.get('username'), ip=get_client_ip())
    build_cache_async()
    return jsonify({'ok': True})

@app.route('/api/cache-status')
@require_auth
def cache_status():
    data = load_data()
    return jsonify({
        'building': _cache_building,
        'built_at': data['cache'].get('built_at'),
        'count':    len(data['cache'].get('results', [])),
        'cache_interval_hours': data['config'].get('cache_interval_hours', 24)
    })

@app.route('/api/flag/<req_id>', methods=['POST'])
@require_auth
def set_flag(req_id):
    body    = request.json or {}
    flagged = body.get('flagged', False)
    note    = body.get('note', '')
    username = request.session['username']
    ip       = get_client_ip()

    with data_transaction() as data:
        # Block flagging protected items for non-admins
        if flagged and not request.session.get('is_admin'):
            if data['protected'].get(req_id):
                return jsonify({'error': 'This item has been protected by an admin.'}), 403

        # Find title for logging
        title = next((r['title'] for r in data['cache'].get('results', []) if r['req_id'] == req_id), req_id)

        if flagged:
            data['flags'][req_id] = {
                'flagged_by': username,
                'note': note, 'flagged_at': time.time()
            }
            write_log('flag', f'Flagged for deletion: "{title}"{f" — note: {note}" if note else ""}', username=username, ip=ip)
        else:
            data['flags'].pop(req_id, None)
            write_log('flag', f'Flag removed: "{title}"', username=username, ip=ip)

    return jsonify({'ok': True})

@app.route('/api/protect/<req_id>', methods=['POST'])
@require_admin
def set_protect(req_id):
    body      = request.json or {}
    protected = body.get('protected', False)
    username  = request.session['username']
    ip        = get_client_ip()

    with data_transaction() as data:
        title = next((r['title'] for r in data['cache'].get('results', []) if r['req_id'] == req_id), req_id)

        if protected:
            data['protected'][req_id] = {
                'protected_by': username,
                'protected_at': time.time()
            }
            data['flags'].pop(req_id, None)
            write_log('admin', f'Protected (keep): "{title}"', username=username, ip=ip)
        else:
            data['protected'].pop(req_id, None)
            write_log('admin', f'Protection removed: "{title}"', username=username, ip=ip)

    return jsonify({'ok': True})

@app.route('/api/permissions', methods=['GET'])
@require_admin
def get_permissions():
    data  = load_data()
    cfg   = decrypt_config(data['config'])
    users = emby_get_users(cfg['emby_url'], cfg['emby_key'])
    return jsonify({'permissions': data['permissions'],
                    'users': [{'id': u['Id'], 'name': u['Name']} for u in users]})

@app.route('/api/permissions', methods=['POST'])
@require_admin
def set_permissions():
    body     = request.json or {}
    username = request.session['username']
    ip       = get_client_ip()
    user_id  = body.get('user_id')
    can_see  = body.get('can_see', [])
    if not user_id or not isinstance(can_see, list):
        return jsonify({'error': 'user_id and can_see list required'}), 400
    with data_transaction() as data:
        data['permissions'][user_id] = can_see
    write_log('permissions', f'Permissions updated for user ID {user_id} — can see: {can_see}', username=username, ip=ip)
    return jsonify({'ok': True})

@app.route('/api/config', methods=['GET'])
@require_admin
def get_config():
    data = load_data()
    return jsonify(mask_config(decrypt_config(data['config'])))

@app.route('/api/config', methods=['POST'])
@require_admin
def update_config():
    body     = request.json or {}
    username = request.session['username']
    ip       = get_client_ip()
    changed  = []
    with data_transaction() as data:
        cfg = decrypt_config(data['config'])
        for key in ['emby_url', 'emby_key', 'overseerr_url', 'overseerr_key', 'overseerr_public_url', 'cache_interval_hours']:
            if key not in body:
                continue
            val = body[key]
            # Skip masked placeholder and encrypted strings (starts with gAAAAA = Fernet token)
            if val == '••••••••':
                continue
            if isinstance(val, str) and val.startswith('gAAAAA'):
                continue
            cfg[key] = val
            changed.append(key if 'key' not in key else f'{key} (re-saved)')
        data['config'] = encrypt_config(cfg)
    if changed:
        write_log('admin', f'Config updated — fields changed: {", ".join(changed)}', username=username, ip=ip)
    return jsonify({'ok': True})

@app.route('/api/logs')
@require_admin
def get_logs():
    return jsonify({'logs': read_log(200)})

# ── Arr instance helpers ──────────────────────────────────────────────────────

def get_arr_instances(cfg):
    instances = cfg.get('arr_instances', [])
    result = []
    for inst in instances:
        result.append({
            'id':               inst.get('id', ''),
            'seerr_service_id': inst.get('seerr_service_id', ''),
            'name':             inst.get('custom_name') or inst.get('name', ''),
            'type':             inst.get('type', ''),
            'url':              inst.get('url', ''),
            'key':              decrypt_value(inst.get('key', ''))
        })
    return result

def encrypt_arr_instances(instances):
    result = []
    for inst in instances:
        existing_key = inst.get('key', '')
        if existing_key and existing_key != '••••••••':
            encrypted_key = encrypt_value(existing_key)
        else:
            encrypted_key = existing_key
        result.append({
            'id':               inst.get('id') or secrets.token_hex(4),
            'seerr_service_id': inst.get('seerr_service_id', ''),
            'name':             inst.get('name', ''),
            'custom_name':      inst.get('custom_name', ''),
            'type':             inst.get('type', ''),
            'url':              inst.get('url', ''),
            'key':              encrypted_key,
            'is4k':             inst.get('is4k', False)
        })
    return result

def mask_arr_instances(instances):
    result = []
    for inst in instances:
        result.append({
            'id':               inst.get('id', ''),
            'seerr_service_id': inst.get('seerr_service_id', ''),
            'name':             inst.get('name', ''),
            'custom_name':      inst.get('custom_name', ''),
            'type':             inst.get('type', ''),
            'url':              inst.get('url', ''),
            'key':              '••••••••' if inst.get('key') else '',
            'is4k':             inst.get('is4k', False)
        })
    return result

def radarr_find_movie(url, key, tmdb_id):
    try:
        resp = req_lib.get(
            f"{url.rstrip('/')}/api/v3/movie",
            params={'tmdbId': tmdb_id, 'apikey': key},
            timeout=10
        )
        if resp.status_code == 200:
            movies = resp.json()
            if movies:
                return movies[0]
    except Exception as e:
        print(f"[delete] Radarr find error: {e}")
    return None

def radarr_delete_movie(url, key, movie_id):
    try:
        resp = req_lib.delete(
            f"{url.rstrip('/')}/api/v3/movie/{movie_id}",
            params={'apikey': key, 'deleteFiles': 'true', 'addImportExclusion': 'false'},
            timeout=15
        )
        return resp.status_code in (200, 204)
    except Exception as e:
        print(f"[delete] Radarr delete error: {e}")
        return False

def sonarr_find_series(url, key, tvdb_id=None, tmdb_id=None):
    try:
        resp = req_lib.get(
            f"{url.rstrip('/')}/api/v3/series",
            params={'apikey': key},
            timeout=10
        )
        if resp.status_code == 200:
            for s in resp.json():
                if tvdb_id and str(s.get('tvdbId', '')) == str(tvdb_id):
                    return s
                if tmdb_id and str(s.get('tmdbId', '')) == str(tmdb_id):
                    return s
    except Exception as e:
        print(f"[delete] Sonarr find error: {e}")
    return None

def sonarr_delete_series(url, key, series_id):
    try:
        resp = req_lib.delete(
            f"{url.rstrip('/')}/api/v3/series/{series_id}",
            params={'apikey': key, 'deleteFiles': 'true'},
            timeout=15
        )
        return resp.status_code in (200, 204)
    except Exception as e:
        print(f"[delete] Sonarr delete error: {e}")
        return False

def overseerr_delete_request(overseerr_url, overseerr_key, request_id):
    try:
        resp = req_lib.delete(
            f"{overseerr_url.rstrip('/')}/api/v1/request/{request_id}",
            headers={"X-Api-Key": overseerr_key},
            timeout=10
        )
        return resp.status_code in (200, 204)
    except Exception as e:
        print(f"[delete] Seerr delete error: {e}")
        return False

def overseerr_get_request(overseerr_url, overseerr_key, request_id):
    try:
        resp = req_lib.get(
            f"{overseerr_url.rstrip('/')}/api/v1/request/{request_id}",
            headers={"X-Api-Key": overseerr_key},
            timeout=10
        )
        if resp.status_code == 200:
            return resp.json()
    except Exception as e:
        print(f"[delete] Seerr get request error: {e}")
    return None

# ── Arr config routes ─────────────────────────────────────────────────────────

@app.route('/api/config/arr', methods=['GET'])
@require_admin
def get_arr_config():
    data = load_data()
    cfg  = data.get('config', {})
    instances = cfg.get('arr_instances', [])
    return jsonify({'arr_instances': mask_arr_instances(instances)})

@app.route('/api/config/arr', methods=['POST'])
@require_admin
def update_arr_config():
    body      = request.json or {}
    username  = request.session['username']
    ip        = get_client_ip()
    instances = body.get('arr_instances', [])
    with data_transaction() as data:
        # Preserve existing encrypted keys for instances that sent back ••••••••
        existing = {i['id']: i for i in data['config'].get('arr_instances', [])}
        for inst in instances:
            iid = inst.get('id', '')
            if inst.get('key') == '••••••••' and iid in existing:
                inst['key'] = decrypt_value(existing[iid].get('key', ''))
        data['config']['arr_instances'] = encrypt_arr_instances(instances)
    write_log('admin', f'Arr instances updated — {len(instances)} instance(s) configured', username=username, ip=ip)
    return jsonify({'ok': True})

# ── Delete route ──────────────────────────────────────────────────────────────

@app.route('/api/delete/<req_id>', methods=['POST'])
@require_admin
def delete_item(req_id):
    data     = load_data()
    cfg      = decrypt_config(data['config'])
    username = request.session['username']
    ip       = get_client_ip()

    # Find item in cache
    cache_item = next((r for r in data['cache'].get('results', []) if r['req_id'] == req_id), None)
    if not cache_item:
        return jsonify({'error': 'Item not found in cache'}), 404

    title    = cache_item.get('title', req_id)
    mtype    = cache_item.get('type', 'Movie')
    tmdb_id  = cache_item.get('tmdb_id', '')
    tvdb_id  = cache_item.get('tvdb_id', '')

    # Fallback: parse from overseerr_link if not stored directly
    if not tmdb_id:
        link = cache_item.get('overseerr_link', '')
        if '/movie/' in link:
            tmdb_id = link.split('/movie/')[-1]
        elif '/tv/' in link:
            tmdb_id = link.split('/tv/')[-1]

    steps    = []
    warnings = []
    errors   = []

    # ── Step 1: Check Seerr for the request ──────────────────────────────────
    seerr_request = overseerr_get_request(cfg['overseerr_url'], cfg['overseerr_key'], req_id)
    if not seerr_request:
        warnings.append('This item was not found in Seerr — it may have been added directly to Radarr/Sonarr by an admin rather than requested through Seerr.')

    # ── Step 2: Find which Arr instance owns it ───────────────────────────────
    arr_instances = get_arr_instances(cfg)
    arr_hit       = None
    arr_item_id   = None

    # Match by cached serviceId first (precise), then fall back to searching all instances
    cache_svc_id = cache_item.get('service_id', '')
    if cache_svc_id:
        for inst in arr_instances:
            if inst.get('seerr_service_id') == cache_svc_id:
                arr_hit = inst
                break

    if arr_hit:
        # Found exact instance — get item ID within it
        if mtype == 'Movie' and tmdb_id:
            found = radarr_find_movie(arr_hit['url'], arr_hit['key'], tmdb_id)
            if found:
                arr_item_id = found['id']
        elif mtype == 'Series':
            found = sonarr_find_series(arr_hit['url'], arr_hit['key'],
                                       tvdb_id=cache_item.get('tvdb_id'),
                                       tmdb_id=tmdb_id)
            if found:
                arr_item_id = found['id']
        if not arr_item_id:
            arr_hit = None  # Instance found but item not in it — fallback

    if not arr_hit:
        # Fallback: search all instances of matching type
        service_type = 'radarr' if mtype == 'Movie' else 'sonarr'
        for inst in arr_instances:
            if inst['type'].lower() != service_type:
                continue
            if mtype == 'Movie' and tmdb_id:
                found = radarr_find_movie(inst['url'], inst['key'], tmdb_id)
                if found:
                    arr_hit = inst
                    arr_item_id = found['id']
                    break
            elif mtype == 'Series':
                found = sonarr_find_series(inst['url'], inst['key'],
                                           tvdb_id=cache_item.get('tvdb_id'),
                                           tmdb_id=tmdb_id)
                if found:
                    arr_hit = inst
                    arr_item_id = found['id']
                    break

    if not arr_hit and not arr_instances:
        warnings.append('No Arr instances configured — cannot delete from Radarr/Sonarr. Configure them in Settings first. Media files (if any) will remain on disk.')
    elif not arr_hit:
        warnings.append(f'Could not find this item in any configured {"Radarr" if mtype=="Movie" else "Sonarr"} instance — media files (if any) will remain on disk untracked.')

    # ── Step 3: Delete from Arr ───────────────────────────────────────────────
    if arr_hit and arr_item_id:
        if mtype == 'Movie':
            ok = radarr_delete_movie(arr_hit['url'], arr_hit['key'], arr_item_id)
        else:
            ok = sonarr_delete_series(arr_hit['url'], arr_hit['key'], arr_item_id)
        if ok:
            steps.append(f'Removed from {arr_hit["name"]} (files deleted)')
        else:
            errors.append(f'Failed to delete from {arr_hit["name"]} — check Arr logs')

    # ── Step 4: Delete from Seerr ─────────────────────────────────────────────
    if seerr_request:
        ok = overseerr_delete_request(cfg['overseerr_url'], cfg['overseerr_key'], req_id)
        if ok:
            steps.append('Removed from Seerr')
        else:
            errors.append('Failed to remove from Seerr')

    # ── Step 5: Only clean up if Arr deletion succeeded (or no Arr needed) ─────
    # If there were errors in the Arr step, abort — don't remove from Seerr or cache
    # so the admin can fix the Arr config and retry.
    arr_attempted  = bool(arr_hit)
    arr_succeeded  = arr_attempted and not any('Failed to delete' in e for e in errors)

    if errors and arr_attempted and not arr_succeeded:
        # Arr deletion failed — abort everything, don't touch Seerr or cache
        summary = f'Delete ABORTED for "{title}" — Arr deletion failed: {"; ".join(errors)}'
        write_log('admin', summary, username=username, ip=ip)
        return jsonify({
            'ok': False,
            'steps': steps,
            'warnings': warnings,
            'errors': errors + ['Item NOT removed from Seerr or Watchdog cache — fix the Arr error and try again.'],
            'title': title,
            'aborted': True
        })

    # Safe to clean up Seerr and cache
    with data_transaction() as data:
        data['flags'].pop(req_id, None)
        data['protected'].pop(req_id, None)
        data.get('season_flags', {}).pop(req_id, None)
        data.get('requester_overrides', {}).pop(req_id, None)
        data['cache']['results'] = [r for r in data['cache'].get('results', []) if r['req_id'] != req_id]

    summary = f'Deleted "{title}" — steps: {"; ".join(steps) if steps else "none completed"}'
    if warnings:
        summary += f' — warnings: {"; ".join(warnings)}'
    if errors:
        summary += f' — errors: {"; ".join(errors)}'

    write_log('admin', summary, username=username, ip=ip)

    return jsonify({
        'ok': not errors,
        'steps': steps,
        'warnings': warnings,
        'errors': errors,
        'title': title,
        'aborted': False
    })


# ── Seerr Arr sync ────────────────────────────────────────────────────────────

@app.route('/api/config/arr/sync', methods=['POST'])
@require_admin
def sync_arr_from_seerr():
    data     = load_data()
    cfg      = decrypt_config(data['config'])
    username = request.session['username']
    ip       = get_client_ip()

    synced_services = fetch_seerr_services(cfg['overseerr_url'], cfg['overseerr_key'])
    if not synced_services:
        return jsonify({'error': 'No services returned from Seerr — check Overseerr URL and API key'}), 400

    # Build lookup of synced services by composite ID
    synced_map = {s['seerr_service_id']: s for s in synced_services}

    with data_transaction() as data:
        # Walk existing instances in their current order — update URL/name but preserve custom_name, key, position
        current = data['config'].get('arr_instances', [])
        updated = []
        seen_ids = set()
        for inst in current:
            sid = inst.get('seerr_service_id', '')
            itype = inst.get('type', '')
            # Match by composite ID or migrate from old bare ID
            composite = sid if ':' in sid else f"{itype}:{sid}"
            svc = synced_map.get(composite)
            if svc:
                updated.append({
                    'id':               inst.get('id') or secrets.token_hex(4),
                    'seerr_service_id': composite,   # migrate to composite if needed
                    'name':             svc['name'],
                    'custom_name':      inst.get('custom_name', ''),  # never overwrite
                    'type':             svc['type'],
                    'url':              svc['url'],   # update URL from Seerr
                    'key':              inst.get('key', ''),           # preserve key
                    'is4k':             svc.get('is4k', False)
                })
                seen_ids.add(composite)
            else:
                updated.append(inst)  # keep unrecognised instances untouched

        # Append genuinely new instances not already in the list
        for svc in synced_services:
            if svc['seerr_service_id'] not in seen_ids:
                updated.append({
                    'id':               secrets.token_hex(4),
                    'seerr_service_id': svc['seerr_service_id'],
                    'name':             svc['name'],
                    'custom_name':      '',
                    'type':             svc['type'],
                    'url':              svc['url'],
                    'key':              '',
                    'is4k':             svc.get('is4k', False)
                })

        data['config']['arr_instances'] = updated

    write_log('admin', f'Arr instances synced from Seerr — {len(updated)} instance(s)', username=username, ip=ip)
    return jsonify({'ok': True, 'arr_instances': mask_arr_instances(updated), 'count': len(updated)})


# ── Season flags ──────────────────────────────────────────────────────────────

@app.route('/api/seasons/<req_id>', methods=['GET'])
@require_auth
def get_seasons(req_id):
    """Get season data for a TV show from Emby + Seerr."""
    data = load_data()
    cfg  = decrypt_config(data['config'])

    cache_item = next((r for r in data['cache'].get('results', []) if r['req_id'] == req_id), None)
    if not cache_item:
        return jsonify({'error': 'Item not found'}), 404
    if cache_item.get('type') != 'Series':
        return jsonify({'error': 'Season flags are only for TV shows'}), 400

    emby_item_id = None
    tmdb_id      = cache_item.get('tmdb_id', '')
    tvdb_id      = cache_item.get('tvdb_id', '')

    # Find in Emby — use AnyProviderIdEquals so the server does the matching.
    # (Previously this fetched with Limit:1 and matched client-side, which only
    # ever saw one arbitrary series from the whole library and almost always missed.)
    provider_filters = []
    if tmdb_id:
        provider_filters.append(f'tmdb.{tmdb_id}')
    if tvdb_id:
        provider_filters.append(f'tvdb.{tvdb_id}')
    try:
        er = req_lib.get(
            f"{cfg['emby_url']}/Items",
            params={'Recursive': 'true', 'IncludeItemTypes': 'Series',
                    'AnyProviderIdEquals': ','.join(provider_filters),
                    'Fields': 'ProviderIds', 'Limit': 5,
                    'api_key': cfg['emby_key']},
            timeout=10
        )
        for item in er.json().get('Items', []):
            p = item.get('ProviderIds', {})
            if str(p.get('Tmdb', p.get('tmdb', ''))) == tmdb_id or str(p.get('Tvdb', p.get('tvdb', ''))) == tvdb_id:
                emby_item_id = item['Id']
                break
    except Exception as e:
        print(f"[seasons] Emby lookup error: {e}")

    seasons = []
    if emby_item_id:
        try:
            sr = req_lib.get(
                f"{cfg['emby_url']}/Shows/{emby_item_id}/Seasons",
                params={'api_key': cfg['emby_key'], 'Fields': 'RecursiveItemCount'},
                timeout=10
            )
            for s in sr.json().get('Items', []):
                snum = s.get('IndexNumber')
                if snum is None:
                    continue
                seasons.append({
                    'season':        snum,
                    'name':          s.get('Name', f'Season {snum}'),
                    'episode_count': s.get('RecursiveItemCount', 0),
                    'in_emby':       True
                })
        except Exception as e:
            print(f"[seasons] Emby seasons error: {e}")

    # Merge Seerr season request data
    try:
        seerr_req = overseerr_get_request(cfg['overseerr_url'], cfg['overseerr_key'], req_id)
        if seerr_req:
            for ss in seerr_req.get('seasons', []):
                snum = ss.get('seasonNumber')
                if snum is None:
                    continue
                existing = next((s for s in seasons if s['season'] == snum), None)
                if existing:
                    existing['seerr_status'] = ss.get('status')
                    existing['requested']    = True
                else:
                    seasons.append({
                        'season':        snum,
                        'name':          f'Season {snum}',
                        'episode_count': 0,
                        'in_emby':       False,
                        'seerr_status':  ss.get('status'),
                        'requested':     True
                    })
    except Exception as e:
        print(f"[seasons] Seerr season error: {e}")

    seasons.sort(key=lambda s: s['season'])
    current_flags = data.get('season_flags', {}).get(req_id, [])
    return jsonify({'seasons': seasons, 'flagged_seasons': current_flags})


@app.route('/api/flag/seasons/<req_id>', methods=['POST'])
@require_auth
def flag_seasons(req_id):
    """Flag specific seasons of a TV show for deletion."""
    body     = request.json or {}
    username = request.session['username']
    ip       = get_client_ip()
    seasons  = body.get('seasons', [])  # list of season numbers

    with data_transaction() as data:
        cache_item = next((r for r in data['cache'].get('results', []) if r['req_id'] == req_id), None)
        title      = cache_item.get('title', req_id) if cache_item else req_id

        # Block if protected
        if not request.session.get('is_admin') and data['protected'].get(req_id):
            return jsonify({'error': 'This item has been protected by an admin.'}), 403

        if seasons:
            data['season_flags'][req_id] = seasons
            write_log('flag', f'Season flag set for "{title}" — seasons: {seasons}', username=username, ip=ip)
        else:
            data['season_flags'].pop(req_id, None)
            write_log('flag', f'Season flags cleared for "{title}"', username=username, ip=ip)

        # Update cache item's season_flags in place
        for r in data['cache'].get('results', []):
            if r['req_id'] == req_id:
                r['season_flags'] = seasons
                break

    return jsonify({'ok': True})


@app.route('/api/delete/seasons/<req_id>', methods=['POST'])
@require_admin
def delete_seasons(req_id):
    """Delete specific seasons from Sonarr. Show stays in Seerr and Watchdog."""
    data     = load_data()
    cfg      = decrypt_config(data['config'])
    username = request.session['username']
    ip       = get_client_ip()
    body     = request.json or {}
    seasons  = body.get('seasons', [])

    cache_item = next((r for r in data['cache'].get('results', []) if r['req_id'] == req_id), None)
    if not cache_item:
        return jsonify({'error': 'Item not found in cache'}), 404
    if cache_item.get('type') != 'Series':
        return jsonify({'error': 'Season deletion only applies to TV shows'}), 400

    title    = cache_item.get('title', req_id)
    tvdb_id  = cache_item.get('tvdb_id', '')
    tmdb_id  = cache_item.get('tmdb_id', '')
    steps    = []
    errors   = []

    # Find Sonarr instance
    arr_instances  = get_arr_instances(cfg)
    cache_svc_id   = cache_item.get('service_id', '')
    sonarr_inst    = None
    sonarr_item_id = None

    if cache_svc_id:
        for inst in arr_instances:
            if inst.get('seerr_service_id') == cache_svc_id and inst['type'] == 'sonarr':
                sonarr_inst = inst
                break

    if not sonarr_inst:
        for inst in arr_instances:
            if inst['type'] == 'sonarr':
                found = sonarr_find_series(inst['url'], inst['key'], tvdb_id=tvdb_id, tmdb_id=tmdb_id)
                if found:
                    sonarr_inst = inst
                    sonarr_item_id = found['id']
                    break

    if sonarr_inst and not sonarr_item_id:
        found = sonarr_find_series(sonarr_inst['url'], sonarr_inst['key'], tvdb_id=tvdb_id, tmdb_id=tmdb_id)
        if found:
            sonarr_item_id = found['id']

    if not sonarr_inst:
        return jsonify({'error': 'Could not find show in any configured Sonarr instance'}), 404

    if not sonarr_item_id:
        return jsonify({'error': f'Show not found in {sonarr_inst["name"]}'}), 404

    # Delete episode files for each flagged season
    for season_num in seasons:
        try:
            # Get episode files for this season
            ef_resp = req_lib.get(
                f"{sonarr_inst['url'].rstrip('/')}/api/v3/episodefile",
                params={'apikey': sonarr_inst['key'], 'seriesId': sonarr_item_id, 'seasonNumber': season_num},
                timeout=10
            )
            if ef_resp.status_code == 200:
                file_ids = [ef['id'] for ef in ef_resp.json()]
                if file_ids:
                    # Bulk delete episode files
                    del_resp = req_lib.delete(
                        f"{sonarr_inst['url'].rstrip('/')}/api/v3/episodefile/bulk",
                        json={'episodeFileIds': file_ids},
                        headers={'X-Api-Key': sonarr_inst['key']},
                        timeout=15
                    )
                    if del_resp.status_code in (200, 204):
                        steps.append(f'Season {season_num}: {len(file_ids)} file(s) deleted')
                        # Unmonitor the season in Sonarr
                        mon_resp = req_lib.put(
                            f"{sonarr_inst['url'].rstrip('/')}/api/v3/season/monitor",
                            json={'seriesId': sonarr_item_id, 'seasonNumber': season_num, 'monitored': False},
                            headers={'X-Api-Key': sonarr_inst['key']},
                            timeout=10
                        )
                        if mon_resp.status_code not in (200, 202, 204):
                            steps.append(f'Season {season_num}: files deleted but unmonitor failed (HTTP {mon_resp.status_code}) — Sonarr may re-download')
                    else:
                        errors.append(f'Season {season_num}: file deletion failed')
                else:
                    steps.append(f'Season {season_num}: no files found (already deleted?)')
        except Exception as e:
            errors.append(f'Season {season_num}: error — {e}')

    # Clear season flags on success
    if not errors:
        with data_transaction() as data:
            data['season_flags'].pop(req_id, None)
            for r in data['cache'].get('results', []):
                if r['req_id'] == req_id:
                    r['season_flags'] = []
                    break

    summary = f'Season delete for "{title}" seasons {seasons} — {"; ".join(steps)}'
    if errors:
        summary += f' — errors: {"; ".join(errors)}'
    write_log('admin', summary, username=username, ip=ip)

    return jsonify({'ok': not errors, 'steps': steps, 'errors': errors, 'title': title})


# ── Reassign requester ────────────────────────────────────────────────────────

@app.route('/api/reassign/<req_id>', methods=['POST'])
@require_admin
def reassign_requester(req_id):
    """Reassign a cache item to a different Emby user (local only, does not affect Seerr)."""
    body         = request.json or {}
    username     = request.session['username']
    ip           = get_client_ip()
    new_username = body.get('username', '').strip()
    new_emby_id  = body.get('emby_id', '').strip()

    if not new_username:
        return jsonify({'error': 'username required'}), 400

    updated = False
    title   = req_id
    old_requester = ''
    with data_transaction() as data:
        for r in data['cache'].get('results', []):
            if r['req_id'] == req_id:
                old_requester          = r.get('requested_by', '')
                title                  = r.get('title', req_id)
                r['requested_by']      = new_username
                r['requester_emby_id'] = new_emby_id or None
                updated                = True
                break

        if not updated:
            return jsonify({'error': 'Item not found in cache'}), 404

        # Persist override so it survives cache rebuilds
        if 'requester_overrides' not in data:
            data['requester_overrides'] = {}
        data['requester_overrides'][req_id] = {
            'username': new_username,
            'emby_id':  new_emby_id or None
        }

    write_log('admin', f'Requester reassigned for "{title}": {old_requester} → {new_username}', username=username, ip=ip)
    return jsonify({'ok': True})

if __name__ == '__main__':
    try:
        from waitress import serve
        print('[server] Starting with waitress on 0.0.0.0:5000')
        serve(app, host='0.0.0.0', port=5000, threads=8)
    except ImportError:
        print('[server] waitress not installed — falling back to Flask dev server '
              '(add "waitress" to requirements.txt for production use)')
        app.run(host='0.0.0.0', port=5000, debug=False)
