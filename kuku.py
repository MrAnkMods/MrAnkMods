# ============================================================
# भाग 1 : imports, token manager, JWT helper, account‑safe logic
#          login/OTP/session routes
# ============================================================
import os
import asyncio
import time
import orjson
import base64
import json
import logging
from urllib.parse import parse_qs
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from utils import build_headers, kuku_client, get_cached_data, set_cached_data
from utils.cache import clear_cache

logger = logging.getLogger("kuku-proxy.routes")
router = APIRouter()
api_base_url: str = "https://api.kukufm.com"

# ============================================================
# MASTER TOKEN AUTO-REFRESH (env-only, no hardcoded fallback)
# ============================================================
BACKUP_MASTER_TOKEN = os.getenv("KUKU_MASTER_TOKEN")
BACKUP_REFRESH_TOKEN = os.getenv("KUKU_REFRESH_TOKEN")

if not BACKUP_MASTER_TOKEN or not BACKUP_REFRESH_TOKEN:
    logger.error(
        "❌ KUKU_MASTER_TOKEN and KUKU_REFRESH_TOKEN must be set in environment variables! "
        "Proxy will fail without valid tokens."
    )

MASTER_ACCESS_TOKEN = BACKUP_MASTER_TOKEN
REFRESH_TOKEN = BACKUP_REFRESH_TOKEN
LAST_REFRESH_TIME = 0.0
TOKEN_EXPIRY_THRESHOLD = 3600

_token_refresh_lock = asyncio.Lock()

async def get_valid_master_token(force_refresh: bool = False) -> str:
    global MASTER_ACCESS_TOKEN, REFRESH_TOKEN, LAST_REFRESH_TIME

    if not MASTER_ACCESS_TOKEN and not REFRESH_TOKEN:
        logger.error("No tokens available. Set KUKU_MASTER_TOKEN and KUKU_REFRESH_TOKEN.")
        return None

    current_time = time.time()
    needs_refresh = (
        force_refresh or
        (current_time - LAST_REFRESH_TIME > TOKEN_EXPIRY_THRESHOLD) or
        not MASTER_ACCESS_TOKEN or
        (BACKUP_MASTER_TOKEN and MASTER_ACCESS_TOKEN == BACKUP_MASTER_TOKEN)
    )

    if not needs_refresh:
        return MASTER_ACCESS_TOKEN

    async with _token_refresh_lock:
        current_time = time.time()
        if not force_refresh and (current_time - LAST_REFRESH_TIME <= TOKEN_EXPIRY_THRESHOLD) and MASTER_ACCESS_TOKEN != BACKUP_MASTER_TOKEN:
            return MASTER_ACCESS_TOKEN

        logger.info("[TOKEN REFRESH] Fetching fresh session token using refresh_token...")
        refresh_url = f"{api_base_url}/api/v1.1/users/get-session-token/?app_build_number=5080600&app_version=5.8.6"

        static_auth_headers = {
            "install-source": "google_play",
            "app-version": "5.8.6",
            "user-agent": "kukufm-android-reels/5.8.6",
            "package-name": "com.vlv.aravali.reels",
            "build-number": "5080600",
            "content-type": "application/x-www-form-urlencoded"
        }

        if REFRESH_TOKEN:
            form_data = {
                "app_name": "com.vlv.aravali.reels",
                "os_type": "android",
                "app_build_number": "5080600",
                "installed_version": "5.8.6",
                "refresh_token": REFRESH_TOKEN
            }
        else:
            logger.warning("No refresh token available, falling back to device fingerprint (likely to fail).")
            form_data = {
                "app_name": "com.vlv.aravali.reels",
                "os_type": "android",
                "app_build_number": "5080600",
                "installed_version": "5.8.6",
                "advertising_id": "87783c53-7ff4-4ef3-8bc9-f8505b2c6c0b",
                "android_id": "3ed4104c422e1abe",
                "is_upi_app_installed": "false"
            }

        max_retries = 3
        for attempt in range(max_retries):
            try:
                status, data = await kuku_client.make_post_request_form(
                    url=refresh_url,
                    headers=static_auth_headers,
                    form_data=form_data
                )

                if status == 200 and isinstance(data, dict):
                    new_token = data.get("access_token")
                    if not new_token and isinstance(data.get("data"), dict):
                        new_token = data["data"].get("access_token")

                    if new_token:
                        MASTER_ACCESS_TOKEN = f"jwt {new_token}" if not new_token.startswith("jwt ") else new_token
                        new_refresh = data.get("refresh_token")
                        if new_refresh:
                            REFRESH_TOKEN = new_refresh
                            logger.info("[TOKEN REFRESH] Refresh token updated.")
                        LAST_REFRESH_TIME = time.time()
                        logger.info("[TOKEN REFRESH] Success! Master token rotated.")
                        return MASTER_ACCESS_TOKEN
                    else:
                        logger.warning(f"[TOKEN REFRESH] Attempt {attempt+1}/{max_retries}: No access_token in response.")
                else:
                    logger.warning(f"[TOKEN REFRESH] Attempt {attempt+1}/{max_retries}: Status {status}")

            except Exception as e:
                logger.error(f"[TOKEN REFRESH ERROR] Attempt {attempt+1}/{max_retries}: {e}")

            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)

        logger.error("[TOKEN REFRESH] All attempts failed. Using current token (may be invalid).")
        LAST_REFRESH_TIME = time.time()
        return MASTER_ACCESS_TOKEN


# ============================================================
# JWT decode helper – extract user_id from proxy master token
# ============================================================
def get_user_id_from_token(token: str) -> int:
    try:
        if token.startswith("jwt "):
            token = token[4:]
        payload_b64 = token.split(".")[1]
        payload_b64 += "=" * (4 - len(payload_b64) % 4)
        payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        return payload.get("user_id", 0)
    except Exception:
        return 0


# ============================================================
# ACCOUNT‑SAFE LANGUAGE ENFORCEMENT
#   केवल तभी भाषा बदलें जब ज़रूरत हो (हर ऐप स्टार्ट पर नहीं)
#   और कोशिश करें कि पुरानी भाषा हिंदी हो तो दोबारा रिक्वेस्ट न भेजें
# ============================================================
_last_lang_sync = 0.0
LANG_SYNC_INTERVAL = 3600  # हर घंटे में एक बार से ज़्यादा नहीं

async def enforce_hindi_language(token: str):
    global _last_lang_sync
    now = time.time()
    if now - _last_lang_sync < LANG_SYNC_INTERVAL:
        return  # पिछली सिंक अभी हाल की है, बेवजह अकाउंट को रिस्क न डालें
    _last_lang_sync = now

    user_id = get_user_id_from_token(token)
    if not user_id:
        logger.warning("[LANG] Could not extract user_id, skip language enforcement")
        return
    try:
        url = f"{api_base_url}/api/v1.0/users/{user_id}/languages/"
        headers = {
            "authorization": token,
            "content-type": "application/x-www-form-urlencoded",
            "install-source": "google_play",
            "app-version": "5.8.6",
            "user-agent": "kukufm-android-reels/5.8.6",
            "package-name": "com.vlv.aravali.reels",
            "build-number": "5080600",
        }
        # केवल तभी भेजें जब token बदला हो या 1 घंटा बीत गया हो
        status, _ = await kuku_client.make_post_request_form(
            url=url,
            headers=headers,
            form_data={"language_ids": "1"}   # Hindi
        )
        if status == 200:
            logger.info("[LANG] Language auto‑set to Hindi for user %s", user_id)
        else:
            logger.warning("[LANG] Language set returned %s", status)
    except Exception as e:
        logger.error("[LANG] Background language enforcement failed: %s", e)


# ============================================================
# LOGIN SCREEN CONFIG
# ============================================================
@router.get("/api/v1.0/users/get-user-details-for-advertising-id/")
@router.get("/api/v1.0/users/get-user-details-for-advertising-id")
async def get_user_details_for_ad():
    return JSONResponse({
        "blocking_language_videos": [],
        "default_login_option": "phone_number",
        "login_via_phone_enabled": True,
        "login_via_email_enabled": False,
        "login_via_fb_enabled": False,
        "login_options_layout": "otp_login_first",
        "should_show_truecaller": True,
        "otpless_bg_auth_enabled": True,
        "should_show_otp_login_option": True,
        "is_skip_login": False,
        "is_otpless_enabled": True,
        "shared_login_enable": True,
        "shared_login_timeout_millis": 3000,
        "login_background": "https://images.cdn.kukufm.com/f:webp/https://kukufm.s3.ap-south-1.amazonaws.com/video-thumbnails/hindi_dhoni_499_qtrly_9x16_ftp_frame.jpg",
        "login_video": "https://d1l07mcd18xic4.cloudfront.net/ft_assets/ft_video_dhoni_1_rs_699_qtrly_9x16_kukutv_hindi_v3.m3u8/master.m3u8",
        "show_default_gmail_popup": False,
        "firebase_experiment_enabled": True,
        "skip_onboarding_lang_screen": True,
        "country_iso_code": "IN",
        "single_select": ["hindi"],
        "multi_select": [],
        "is_vip_only": False,
        "primary_app_language_id": 2,
        "is_consumption_only": False,
        "otp_auth_available": True,
        "otp_country_codes": ["91"],
        "user_details": {"full_name": "KUKUFM"},
    })


# ============================================================
# SEND OTP
# ============================================================
@router.post("/api/v1.0/users/auth/send-otp/")
@router.post("/api/v1.0/users/auth/send-otp")
async def send_otp(request: Request):
    try:
        body = await request.body()
        body_json = orjson.loads(body.decode()) if body else {}
        body_json["source"] = "phone_number"

        headers = build_headers()
        headers.pop("authorization", None)
        headers = {k: v for k, v in headers.items() if v}

        kuku_client.clear_cookies()

        status, data = await kuku_client.make_post_request(
            url=api_base_url + "/api/v1.0/users/auth/send-otp/",
            headers=headers,
            post_data=body_json
        )

        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] send-otp: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# VERIFY OTP
# ============================================================
@router.post("/api/v1.0/users/auth/verify-otp/")
@router.post("/api/v1.0/users/auth/verify-otp")
async def verify_otp(request: Request):
    try:
        body = await request.body()
        body_json = orjson.loads(body.decode()) if body else {}

        headers = build_headers()
        headers.pop("authorization", None)
        headers = {k: v for k, v in headers.items() if v}

        status, data = await kuku_client.make_post_request(
            url=api_base_url + "/api/v1.0/users/auth/verify-otp/",
            headers=headers,
            post_data=body_json
        )

        if status == 200 and isinstance(data, dict):
            if "user" in data:
                data["user"]["has_premium"] = True
                data["user"]["is_suspended"] = False

        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] verify-otp: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# OTP-LESS AUTH
# ============================================================
@router.post("/api/v1.0/users/otp-less/")
@router.post("/api/v1.0/users/otp-less")
async def otp_less_login(request: Request):
    return JSONResponse({"token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.fake"})


# ============================================================
# SESSION TOKEN - PREMIUM BYPASS
# ============================================================
@router.post("/api/v1.1/users/get-session-token/")
@router.post("/api/v1.1/users/get-session-token")
async def get_session_token(request: Request):
    try:
        body_text = await request.body()
        parsed_data = parse_qs(body_text.decode())
        body_json = {k: v[0] if len(v) == 1 else v for k, v in parsed_data.items()}

        headers = build_headers()
        headers["content-type"] = "application/x-www-form-urlencoded"
        headers.pop("authorization", None)

        if request.headers.get("client-country"):
            headers["client-country"] = request.headers.get("client-country")
        if request.headers.get("lang"):
            headers["lang"] = request.headers.get("lang")

        headers = {k: v for k, v in headers.items() if v}

        status, data = await kuku_client.make_post_request_form(
            url=api_base_url + "/api/v1.1/users/get-session-token/",
            headers=headers,
            form_data=body_json
        )

        if status == 200 and isinstance(data, dict):
            if "user" in data:
                data["user"]["has_premium"] = True
                data["user"]["is_suspended"] = False
            if "onboarding_data" in data and "user" in data["onboarding_data"]:
                data["onboarding_data"]["user"]["has_premium"] = True

        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] session-token: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)
        
# ============================================================
# भाग 2 : FCM, master config (safe lang enforcement), rewards,
#          home, language, notification, show details, episodes,
#          next episode, more like this, record episode events
# ============================================================
# ... (पिछला भाग 1 का कोड यहाँ ख़त्म होता है)

# ============================================================
# FCM REGISTRATION – prefer client token, fallback to master
# ============================================================
@router.post("/api/v2/users/register-fcm/")
@router.post("/api/v2/users/register-fcm")
async def register_fcm(request: Request):
    try:
        body_text = await request.body()
        parsed_data = parse_qs(body_text.decode())
        body_json = {k: v[0] if len(v) == 1 else v for k, v in parsed_data.items()}

        headers = build_headers()
        headers["content-type"] = "application/x-www-form-urlencoded"

        client_auth = request.headers.get("authorization")
        if client_auth:
            headers["authorization"] = client_auth
        else:
            headers["authorization"] = await get_valid_master_token()

        if request.headers.get("client-country"):
            headers["client-country"] = request.headers.get("client-country")
        if request.headers.get("lang"):
            headers["lang"] = request.headers.get("lang")
        headers = {k: v for k, v in headers.items() if v}

        status, data = await kuku_client.make_post_request_form(
            url=api_base_url + "/api/v2/users/register-fcm/",
            headers=headers,
            form_data=body_json
        )

        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] register-fcm: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# MASTER CONFIG – force token refresh + safe language enforcement
# ============================================================
@router.post("/api/v1.0/config/master/android/")
@router.post("/api/v1.0/config/master/android")
async def get_master_config(request: Request):
    try:
        body = await request.body()
        body_json = orjson.loads(body.decode()) if body else {}

        headers = build_headers()
        # token refresh
        master_token = await get_valid_master_token(force_refresh=True)
        headers["authorization"] = master_token

        # account‑safe language enforcement (background, throttle)
        asyncio.create_task(enforce_hindi_language(master_token))

        if request.headers.get("client-country"):
            headers["client-country"] = request.headers.get("client-country")
        if request.headers.get("lang"):
            headers["lang"] = request.headers.get("lang")
        headers = {k: v for k, v in headers.items() if v}

        status, data = await kuku_client.make_post_request(
            url=api_base_url + "/api/v1.0/config/master/android/",
            headers=headers,
            post_data=body_json
        )

        if status == 200 and isinstance(data, dict) and "config_data" in data:
            data["config_data"]["is_coin_based_monetization"] = False
            data["config_data"]["show_7_days_ft_nudge"] = False

        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] master-config: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# REWARD PROMO COINS (master token)
# ============================================================
@router.post("/api/v2/coins/reward-promo-coins/")
@router.post("/api/v2/coins/reward-promo-coins")
async def reward_promo_coins(request: Request):
    try:
        body = await request.body()
        body_json = orjson.loads(body.decode()) if body else {}

        headers = build_headers()
        headers["authorization"] = await get_valid_master_token()

        if request.headers.get("client-country"):
            headers["client-country"] = request.headers.get("client-country")
        if request.headers.get("lang"):
            headers["lang"] = request.headers.get("lang")
        headers = {k: v for k, v in headers.items() if v}

        status, data = await kuku_client.make_post_request(
            url=api_base_url + "/api/v2/coins/reward-promo-coins/",
            headers=headers,
            post_data=body_json
        )

        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] reward-promo-coins: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# HOME FEED (master token)
# ============================================================
@router.get("/api/v3/home/all/")
@router.get("/api/v3/home/all")
async def get_home_feed(request: Request):
    try:
        cached = get_cached_data(request)
        if cached:
            return JSONResponse(cached, status_code=200)

        url = api_base_url + request.url.path.replace("/kuku", "")
        if request.url.query:
            url += "?" + request.url.query

        headers = build_headers()
        headers["authorization"] = await get_valid_master_token()

        if request.headers.get("lang"):
            headers["lang"] = request.headers.get("lang")
        if request.headers.get("client-country"):
            headers["client-country"] = request.headers.get("client-country")

        incoming_ua = request.headers.get("user-agent")
        if incoming_ua == "kukufm-androids-reels/5.8.6":
            headers["user-agent"] = "kukufm-android-reels/5.8.6"
        elif incoming_ua:
            headers["user-agent"] = incoming_ua

        headers = {k: v for k, v in headers.items() if v}
        status, data = await kuku_client.make_get_request(url=url, headers=headers)

        if status in [401, 403]:
            logger.warning("[HOME FEED] 401/403 encountered. Force refreshing token...")
            headers["authorization"] = await get_valid_master_token(force_refresh=True)
            status, data = await kuku_client.make_get_request(url=url, headers=headers)

        if status == 200:
            set_cached_data(request, data)

        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] home-feed: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# USER LANGUAGE UPDATE – user‑specific action (client token first)
# ============================================================
@router.post("/api/v1.0/users/{user_id}/languages/")
@router.post("/api/v1.0/users/{user_id}/languages")
async def update_user_languages(user_id: str, request: Request):
    try:
        body_text = await request.body()
        parsed_data = parse_qs(body_text.decode())
        body_json = {k: v[0] if len(v) == 1 else v for k, v in parsed_data.items()}
            
        headers = build_headers()
        headers["content-type"] = "application/x-www-form-urlencoded"
        headers["authorization"] = await get_valid_master_token()
        
        if request.headers.get("client-country"): headers["client-country"] = request.headers.get("client-country")
        if request.headers.get("lang"): headers["lang"] = request.headers.get("lang")
        headers = {k: v for k, v in headers.items() if v}
        
        target_url = f"{api_base_url}/api/v1.0/users/{user_id}/languages/"
        status, data = await kuku_client.make_post_request_form(url=target_url, headers=headers, form_data=body_json)
        
        if status == 200:
            logger.info("[LANGUAGE] Language changed! Flushing cache...")
            clear_cache()
            kuku_client.clear_cookies()
        
        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] user-languages: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# NOTIFICATION PREFERENCES (mocked)
# ============================================================
@router.get("/api/v1.0/users/notification-preferences/")
@router.get("/api/v1.0/users/notification-preferences")
async def get_notification_preferences():
    return JSONResponse({
        "groups": [
            {"id": 38, "title": "Subscription Renewal Reminder", "is_selected": True},
            {"id": 3, "title": "Social notifications", "is_selected": True},
            {"id": 2, "title": "Subscribed channel updates", "is_selected": True},
            {"id": 1, "title": "Listening Recommendations", "is_selected": True},
        ]
    })


# ============================================================
# SHOW DETAILS (channel details)
# ============================================================
@router.get("/api/v1.2/channels/{channel_id}/details/")
@router.get("/api/v1.2/channels/{channel_id}/details")
async def get_channel_details(channel_id: int, request: Request):
    try:
        cached = get_cached_data(request)
        if cached:
            return JSONResponse(cached, status_code=200)

        url = api_base_url + request.url.path.replace("/kuku", "")
        if request.url.query:
            url += "?" + request.url.query

        headers = build_headers()
        headers["authorization"] = await get_valid_master_token()

        if request.headers.get("lang"):
            headers["lang"] = request.headers.get("lang")
        if request.headers.get("client-country"):
            headers["client-country"] = request.headers.get("client-country")

        incoming_ua = request.headers.get("user-agent")
        if incoming_ua == "kukufm-androids-reels/5.8.6":
            headers["user-agent"] = "kukufm-android-reels/5.8.6"
        elif incoming_ua:
            headers["user-agent"] = incoming_ua

        headers = {k: v for k, v in headers.items() if v}
        status, data = await kuku_client.make_get_request(url=url, headers=headers)

        if status == 200 and isinstance(data, dict):
            show = data.get("show", {})
            show["is_play_locked"] = False
            if "is_locked" in show:
                show["is_locked"] = False
            resume_ep = data.get("resume_episode")
            if isinstance(resume_ep, dict):
                resume_ep["is_locked"] = False
                resume_ep["is_play_locked"] = False
            episodes = data.get("episodes", [])
            for ep in episodes:
                if isinstance(ep, dict):
                    ep["is_locked"] = False
                    if "is_play_locked" in ep:
                        ep["is_play_locked"] = False
            if "premium_paywall" in data:
                del data["premium_paywall"]
            if "show_access_snippet" in data:
                data["show_access_snippet"]["title"] = "Free Access"
                data["show_access_snippet"]["description"] = "All episodes unlocked"

        if status == 200:
            set_cached_data(request, data)

        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] channel-details: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# EPISODES LIST
# ============================================================
@router.get("/api/v2.3/channels/{channel_id}/episodes/")
@router.get("/api/v2.3/channels/{channel_id}/episodes")
async def get_channel_episodes(channel_id: int, request: Request):
    try:
        cached = get_cached_data(request)
        if cached:
            return JSONResponse(cached, status_code=200)

        url = api_base_url + request.url.path.replace("/kuku", "")
        if request.url.query:
            url += "?" + request.url.query

        headers = build_headers()
        headers["authorization"] = await get_valid_master_token()

        if request.headers.get("lang"):
            headers["lang"] = request.headers.get("lang")
        if request.headers.get("client-country"):
            headers["client-country"] = request.headers.get("client-country")

        incoming_ua = request.headers.get("user-agent")
        if incoming_ua == "kukufm-androids-reels/5.8.6":
            headers["user-agent"] = "kukufm-android-reels/5.8.6"
        elif incoming_ua:
            headers["user-agent"] = incoming_ua

        headers = {k: v for k, v in headers.items() if v}
        status, data = await kuku_client.make_get_request(url=url, headers=headers)

        if status == 200 and isinstance(data, dict):
            show = data.get("show", {})
            show["is_play_locked"] = False
            if "is_locked" in show:
                show["is_locked"] = False
            episodes = data.get("episodes", [])
            for ep in episodes:
                if isinstance(ep, dict):
                    ep["is_locked"] = False
                    if "is_play_locked" in ep:
                        ep["is_play_locked"] = False
                    if "unlock_type" in ep:
                        ep["unlock_type"] = "free"
                    if "premium_tag_string" in ep:
                        ep["premium_tag_string"] = "Free"

        if status == 200:
            set_cached_data(request, data)

        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] channel-episodes: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# NEXT EPISODE AUTOPLAY
# ============================================================
@router.get("/api/v1.2/shows/next-episode-autoplay/")
@router.get("/api/v1.2/shows/next-episode-autoplay")
async def get_next_episode_autoplay(request: Request):
    try:
        cached = get_cached_data(request)
        if cached:
            return JSONResponse(cached, status_code=200)

        url = api_base_url + request.url.path.replace("/kuku", "")
        if request.url.query:
            url += "?" + request.url.query

        headers = build_headers()
        headers["authorization"] = await get_valid_master_token()

        if request.headers.get("lang"):
            headers["lang"] = request.headers.get("lang")
        if request.headers.get("client-country"):
            headers["client-country"] = request.headers.get("client-country")

        incoming_ua = request.headers.get("user-agent")
        if incoming_ua == "kukufm-androids-reels/5.8.6":
            headers["user-agent"] = "kukufm-android-reels/5.8.6"
        elif incoming_ua:
            headers["user-agent"] = incoming_ua

        headers = {k: v for k, v in headers.items() if v}
        status, data = await kuku_client.make_get_request(url=url, headers=headers)

        if status == 200 and isinstance(data, dict):
            next_eps = data.get("next_episodes", [])
            for entry in next_eps:
                ep = entry.get("episode", {})
                if isinstance(ep, dict):
                    ep["is_locked"] = False
                    if "is_play_locked" in ep:
                        ep["is_play_locked"] = False
                    if "unlock_type" in ep:
                        ep["unlock_type"] = "free"
                    if "premium_tag_string" in ep:
                        ep["premium_tag_string"] = "Free"
                show = entry.get("show", {})
                if isinstance(show, dict):
                    show["is_play_locked"] = False
                    if "is_locked" in show:
                        show["is_locked"] = False

        if status == 200:
            set_cached_data(request, data)

        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] next-episode-autoplay: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# MORE LIKE THIS (recommendations)
# ============================================================
# ============================================================
# MORE LIKE THIS (recommendations)
# ============================================================
@router.get("/api/v2/groups/more-like-this/shows/")
@router.get("/api/v2/groups/more-like-this/shows")
async def get_more_like_this(request: Request):
    try:
        cached = get_cached_data(request)
        if cached:
            return JSONResponse(cached, status_code=200)

        url = api_base_url + request.url.path.replace("/kuku", "")
        if request.url.query:
            url += "?" + request.url.query

        headers = build_headers()
        headers["authorization"] = await get_valid_master_token()

        if request.headers.get("lang"):
            headers["lang"] = request.headers.get("lang")
        if request.headers.get("client-country"):
            headers["client-country"] = request.headers.get("client-country")

        incoming_ua = request.headers.get("user-agent")
        if incoming_ua == "kukufm-androids-reels/5.8.6":
            headers["user-agent"] = "kukufm-android-reels/5.8.6"
        elif incoming_ua:
            headers["user-agent"] = incoming_ua

        headers = {k: v for k, v in headers.items() if v}
        status, data = await kuku_client.make_get_request(url=url, headers=headers)

        if status == 200 and isinstance(data, dict):
            shows = data.get("shows", [])
            for show in shows:
                if isinstance(show, dict):
                    if "is_locked" in show:
                        show["is_locked"] = False
                    if "is_play_locked" in show:
                        show["is_play_locked"] = False

        if status == 200:
            set_cached_data(request, data)

        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] more-like-this: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)
     
# ============================================================
# भाग 3 : Catch‑All GET और POST (premium bypass, safe)
# ============================================================
# ... (पिछला भाग 2 का कोड यहाँ ख़त्म होता है)

# ============================================================
# CATCH-ALL GET – /users/* uses client token, else master token
# ============================================================
@router.get("/{rest_of_path:path}")
async def default_get(request: Request):
    try:
        clean_path = request.url.path.replace("/kuku", "")
        url = api_base_url + clean_path + ("?" + request.url.query if request.url.query else "")

        cached = get_cached_data(request)
        if cached:
            return JSONResponse(cached, status_code=200)

        headers = build_headers()

        is_users_endpoint = "/users/" in clean_path
        client_auth = request.headers.get("authorization")
        if is_users_endpoint and client_auth:
            headers["authorization"] = client_auth
        else:
            headers["authorization"] = await get_valid_master_token()

        if request.headers.get("lang"):
            headers["lang"] = request.headers.get("lang")
        if request.headers.get("client-country"):
            headers["client-country"] = request.headers.get("client-country")

        incoming_ua = request.headers.get("user-agent")
        if incoming_ua == "kukufm-androids-reels/5.8.6":
            headers["user-agent"] = "kukufm-android-reels/5.8.6"
        elif incoming_ua:
            headers["user-agent"] = incoming_ua

        headers = {k: v for k, v in headers.items() if v}
        status, data = await kuku_client.make_get_request(url=url, headers=headers)

        if status in [401, 403]:
            logger.warning(f"[CATCH-ALL GET] {status} for {clean_path}. Force refreshing token...")
            if is_users_endpoint and client_auth:
                pass
            else:
                headers["authorization"] = await get_valid_master_token(force_refresh=True)
            status, data = await kuku_client.make_get_request(url=url, headers=headers)

        if status == 200 and isinstance(data, dict):
            if "user" in data and isinstance(data["user"], dict):
                data["user"]["has_premium"] = True
                data["user"]["is_suspended"] = False
            if "show_vip_badge" in data:
                data["show_vip_badge"] = True
            if "is_locked" in data:
                data["is_locked"] = False
            if "episodes" in data and isinstance(data["episodes"], list):
                for ep in data["episodes"]:
                    if isinstance(ep, dict):
                        ep["is_locked"] = False
            if "items" in data and isinstance(data["items"], list):
                for item in data["items"]:
                    if isinstance(item, dict) and "is_locked" in item:
                        item["is_locked"] = False

        if status == 200:
            set_cached_data(request, data)

        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] Catch-All GET {request.url.path}: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)


# ============================================================
# CATCH-ALL POST – same logic: /users/* → client token, else master
# ============================================================
@router.post("/{rest_of_path:path}")
async def default_post(request: Request):
    try:
        body = await request.body()
        url_path = request.url.path.replace("/kuku", "")
        url = api_base_url + url_path
        content_type = request.headers.get("content-type", "")

        headers = build_headers()

        is_users_endpoint = "/users/" in url_path
        client_auth = request.headers.get("authorization")
        if is_users_endpoint and client_auth:
            headers["authorization"] = client_auth
        else:
            headers["authorization"] = await get_valid_master_token()

        if request.headers.get("lang"):
            headers["lang"] = request.headers.get("lang")
        if request.headers.get("client-country"):
            headers["client-country"] = request.headers.get("client-country")

        incoming_ua = request.headers.get("user-agent")
        if incoming_ua == "kukufm-androids-reels/5.8.6":
            headers["user-agent"] = "kukufm-android-reels/5.8.6"
        elif incoming_ua:
            headers["user-agent"] = incoming_ua

        if "application/x-www-form-urlencoded" in content_type:
            headers["content-type"] = "application/x-www-form-urlencoded"
            parsed_data = parse_qs(body.decode())
            form_data = {k: v[0] if isinstance(v, list) and len(v) > 0 else v for k, v in parsed_data.items()}
            headers = {k: v for k, v in headers.items() if v}
            status, data = await kuku_client.make_post_request_form(url=url, headers=headers, form_data=form_data)
        else:
            body_json = orjson.loads(body.decode()) if body else {}
            headers = {k: v for k, v in headers.items() if v}
            status, data = await kuku_client.make_post_request(url=url, headers=headers, post_data=body_json)

        if status in [401, 403]:
            logger.warning(f"[CATCH-ALL POST] {status} for {url_path}. Force refreshing token...")
            if not (is_users_endpoint and client_auth):
                headers["authorization"] = await get_valid_master_token(force_refresh=True)
            if "application/x-www-form-urlencoded" in content_type:
                status, data = await kuku_client.make_post_request_form(url=url, headers=headers, form_data=form_data)
            else:
                status, data = await kuku_client.make_post_request(url=url, headers=headers, post_data=body_json)

        if status == 200 and isinstance(data, dict):
            if "user" in data and isinstance(data["user"], dict):
                data["user"]["has_premium"] = True
                data["user"]["is_suspended"] = False
            if "show_vip_badge" in data:
                data["show_vip_badge"] = True
            if "is_locked" in data:
                data["is_locked"] = False

        response = JSONResponse(data, status_code=status)
        cookies = kuku_client.get_cookies()
        for key, value in cookies.items():
            response.set_cookie(key=key, value=value, path="/", secure=True, httponly=False, samesite="none")
        return response
    except Exception as e:
        logger.error(f"[ERROR] Catch-All POST {request.url.path}: {e}")
        return JSONResponse({"error": str(e)}, status_code=500)                           