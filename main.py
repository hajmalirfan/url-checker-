from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import requests
import tldextract
import whois
from datetime import datetime
from bs4 import BeautifulSoup
from urllib.parse import urlparse

app = FastAPI()

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

def url_features(url):
    score = 0
    reasons = []

    if len(url) > 75:
        score += 20
        reasons.append("URL is too long")

    if "@" in url:
        score += 20
        reasons.append("Contains @ symbol")

    parsed = urlparse(url)
    if parsed.hostname and parsed.hostname.replace(".", "").isdigit():
        score += 30
        reasons.append("IP address used instead of domain")

    return score, reasons

def domain_age_check(domain):
    score = 0
    reasons = []
    try:
        info = whois.whois(domain)
        created = info.creation_date
        if isinstance(created, list):
            created = created[0]
        age = (datetime.now() - created).days
        if age < 180:
            score += 30
            reasons.append("Domain is newly created")
    except:
        score += 20
        reasons.append("WHOIS data unavailable")
    return score, reasons

def https_check(url):
    if not url.startswith("https"):
        return 20, ["No HTTPS detected"]
    return 0, []

def content_check(url):
    score = 0
    reasons = []
    try:
        r = requests.get(url, timeout=5)
        soup = BeautifulSoup(r.text, "html.parser")
        text = soup.get_text().lower()
        for word in ["login", "verify", "password", "urgent"]:
            if word in text:
                score += 5
                reasons.append(f"Keyword found: {word}")
                break
    except:
        score += 10
        reasons.append("Unable to fetch content")
    return score, reasons

@app.get("/check")
def check_url(url: str):
    total = 0
    reasons = []

    domain = tldextract.extract(url).registered_domain

    for func in (url_features, lambda u: domain_age_check(domain), https_check, content_check):
        s, r = func(url)
        total += s
        reasons.extend(r)

    verdict = "LEGITIMATE ✅"
    if total >= 70:
        verdict = "FAKE ❌"
    elif total >= 40:
        verdict = "SUSPICIOUS ⚠️"

    return {"url": url, "score": total, "verdict": verdict, "reasons": reasons}