# The analyst's voice, using an Amazon Polly neural voice.
# Niamh is a calm Irish English voice. Change it with ANALYST_VOICE in .env.
# If Polly isn't available, the dashboard uses the browser's own voice.

import logging
import os

log = logging.getLogger("honeyhome")

REGION = os.getenv("AWS_REGION", "us-east-1")
ANALYST_VOICE = os.getenv("ANALYST_VOICE", "Niamh")
SPEED = "97%"

_polly = None
_polly_failed = False
_cache = {}  # same sentence, same audio, so we don't pay for it twice


def _has_aws():
    try:
        import boto3
        return boto3.Session().get_credentials() is not None
    except Exception:
        return False


def voice_mode():
    if os.getenv("DEMO_MODE", "0") == "1" or _polly_failed or not _has_aws():
        return "browser"
    return "polly"


def _ssml(text):
    safe = text.replace("&", "and").replace("<", "").replace(">", "")
    safe = safe.replace(". ", '. <break time="200ms"/> ').replace("? ", '? <break time="250ms"/> ')
    return f'<speak><prosody rate="{SPEED}">{safe}</prosody></speak>'


def speak(text):
    """Turn text into MP3 audio bytes. Returns None if Polly isn't available."""
    global _polly, _polly_failed

    if voice_mode() == "browser":
        return None
    if text in _cache:
        return _cache[text]

    try:
        if _polly is None:
            import boto3
            _polly = boto3.client("polly", region_name=REGION)

        audio = None
        last_error = None
        for engine in dict.fromkeys(["neural", "standard"]):
            try:
                response = _polly.synthesize_speech(
                    Text=_ssml(text), TextType="ssml",
                    VoiceId=ANALYST_VOICE, Engine=engine, OutputFormat="mp3",
                )
                audio = response["AudioStream"].read()
                break
            except Exception as e:
                last_error = e
        if audio is None:
            raise last_error

        if len(_cache) < 300:
            _cache[text] = audio
        return audio

    except Exception as e:
        log.warning("Polly failed, using browser voice instead: %s", e)
        _polly_failed = True
        return None
