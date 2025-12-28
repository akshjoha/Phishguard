from flask import Flask, render_template, request
from utils import analyze_url
from urllib.parse import urlparse

app = Flask(__name__)

def normalize_url(url):
    """Add scheme if missing"""
    parsed = urlparse(url)
    if not parsed.scheme:
        return "http://" + url
    return url

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None

    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if not url:
            error = "Please enter a valid URL"
        else:
            url = normalize_url(url)
            try:
                verdict, engines, reasons = analyze_url(url)
                result = {
                    "url": url,
                    "verdict": verdict,
                    "engines": engines,
                    "reasons": reasons
                }
            except Exception as e:
                error = f"Error analyzing the website: {str(e)}"

    return render_template("index.html", result=result, error=error)

if __name__ == "__main__":
    app.run(debug=True)
