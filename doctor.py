# Checks that everything HoneyHome needs is set up, and how to fix what isn't.
# Run it with:  python doctor.py

import os
import socket
import sys

problems = 0


def ok(m): print("  [ok]    " + m)
def skip(m): print("  [skip]  " + m)
def bad(m, fix):
    global problems; problems += 1
    print("  [fix]   " + m + "\n          -> " + fix)


print("\nHoneyHome setup check\n\nPython")
if sys.version_info >= (3, 10):
    ok("Python " + sys.version.split()[0])
else:
    bad("Python " + sys.version.split()[0] + " is too old", "install Python 3.10+ from python.org")

print("\nPackages")
missing = []
for mod, name in [("mcp", "mcp"), ("uvicorn", "uvicorn"), ("starlette", "starlette"), ("boto3", "boto3"), ("dotenv", "python-dotenv")]:
    try:
        __import__(mod); ok(name)
    except ImportError:
        missing.append(name); bad(name + " not installed", "pip install -r requirements.txt")
try:
    from mcp.server.mcpserver import MCPServer  # noqa
    ok("MCP SDK v2")
except Exception:
    if "mcp" not in missing:
        bad("MCP SDK too old", 'pip install --upgrade "mcp>=2.3.0"')

print("\nSettings")
here = os.path.dirname(os.path.abspath(__file__))
if os.path.exists(os.path.join(here, ".env")):
    ok(".env found")
    try:
        from dotenv import load_dotenv; load_dotenv(os.path.join(here, ".env"))
    except ImportError: pass
else:
    bad("no .env", "copy .env.example to .env")
demo = os.getenv("DEMO_MODE", "0") == "1"
if demo: skip("DEMO_MODE=1, AWS checks skipped")
if os.path.exists(os.path.join(here, "docs", "index.html")): ok("docs/index.html present")
else: bad("docs/index.html missing", "re-download the project")

for label, port in [("dashboard/MCP", int(os.getenv("PORT", "8000"))), ("camera honeypot", 8081), ("router honeypot", 2323), ("file honeypot", 8445)]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        free = s.connect_ex(("127.0.0.1", port)) != 0
    (ok if free else skip)("port " + str(port) + " (" + label + ") " + ("free" if free else "in use - stop whatever holds it, or it's HoneyHome already running"))

if not demo and "boto3" not in missing:
    import boto3
    region = os.getenv("AWS_REGION", "us-east-1")
    print("\nAWS (region " + region + ")")
    creds = boto3.Session().get_credentials()
    if creds is None:
        bad("no AWS credentials", "run: aws configure  (without it, HoneyHome runs in template/browser-voice mode)")
    else:
        try:
            acct = boto3.client("sts", region_name=region).get_caller_identity()["Account"]
            ok("signed in to AWS account ending " + acct[-4:])
        except Exception as e:
            bad("AWS credentials failed (" + type(e).__name__ + ")", "run: aws configure"); creds = None
    if creds is not None:
        model = os.getenv("BEDROCK_MODEL_ID", "amazon.nova-lite-v1:0")
        try:
            boto3.client("bedrock-runtime", region_name=region).converse(
                modelId=model, messages=[{"role": "user", "content": [{"text": "ok"}]}],
                inferenceConfig={"maxTokens": 5})
            ok("Bedrock works with " + model)
        except Exception as e:
            n = type(e).__name__
            fix = ("enable " + model + " in the Bedrock console (Model access), region " + region) if "AccessDenied" in n \
                  else (model + " not in " + region + "; try AWS_REGION=us-east-1 or another model id") if "Validation" in n \
                  else str(e)[:160]
            bad("Bedrock failed (" + n + ")", fix)
        try:
            boto3.client("polly", region_name=region).synthesize_speech(
                Text="Hello", VoiceId=os.getenv("ANALYST_VOICE", "Niamh"), Engine="neural", OutputFormat="mp3")
            ok("Polly voice " + os.getenv("ANALYST_VOICE", "Niamh"))
        except Exception as e:
            bad("Polly failed (" + type(e).__name__ + ")", "check polly:SynthesizeSpeech permission; browser voice is used as fallback")
        phone = os.getenv("ALERT_PHONE", "")
        if not phone: skip("ALERT_PHONE not set, text alerts off")
        elif not phone.startswith("+"): bad("ALERT_PHONE needs a country code", "write it like +353871234567")
        else: ok("ALERT_PHONE set (verify it in the SNS console if your account is in the SMS sandbox)")

print()
print("All good. Start it with:  python app.py" if problems == 0 else str(problems) + " to fix above. HoneyHome still runs in demo mode meanwhile.")
print()
