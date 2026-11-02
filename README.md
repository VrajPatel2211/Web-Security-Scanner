# Web Security Scanner
A Python tool that checks a website's HTTP security headers, scores them out of 100, grades the result from A+ to F, and tells you how to fix what is missing.
I built it as my final-year project for BSc Computer Science (Cyber Security and Networks) at the University of Hertfordshire. The full write-up is in [`docs/WebVulScannerReport.docx`](docs/WebVulScannerReport.docx).

## What it does
- Fetches the response headers for a URL and analyses them against OWASP-based rules
- Scores the site using weights, so a missing Content-Security-Policy costs more than a missing X-XSS-Protection
- Gives a grade from A+ to F with colour-coded results (green for passing, red for critical)
- Explains what each header does and suggests a fix for each problem
- Exports results to a `.txt` file and keeps a `scanner.log` of scans
- Handles bad input, such as an invalid URL or an SSL/TLS failure, with a clear error message

## Interfaces
| Interface | Built with | Use it for |
|---|---|---|
| Desktop app | Tkinter | Quick scans with a simple GUI |
| Web app | Flask | Scanning from the browser |
| Command line | Python | Scripted or repeated scans |

## Headers checked and scoring
| Priority | Header | Points |
|---|---|---|
| Critical | Content-Security-Policy | 30 |
| Critical | Strict-Transport-Security (HSTS) | 25 |
| Critical | X-Frame-Options | 15 |
| High | X-Content-Type-Options | 10 |
| High | Referrer-Policy | 10 |
| High | Permissions-Policy | 10 |
| Medium | X-XSS-Protection | 5 |

Bonus points are added for having all critical headers (+10) and all high-importance headers (+5). Weak values, such as a CSP set to `none`, do not earn full credit.

| Grade | Score |
|---|---|
| A+ | 95-100 |
| A | 85-94 |

(The full grade scale is in the report.)

## Getting started
```bash
git clone https://github.com/VrajPatel2211/Web-Security-Scanner.git
cd Web-Security-Scanner
pip install -r requirements.txt
```

Run the version you want:

```bash
python gui.py     # desktop app
python app.py     # web app, then open http://127.0.0.1:5000
```

## Example
```
Scanning https://example.com ...

Score: 82/100    Grade: B
Missing: Content-Security-Policy, Permissions-Policy
Fix: add a Content-Security-Policy header, for example
     Content-Security-Policy: default-src 'self'
```

## Testing
Functional tests covered a valid URL, a site with missing headers, an invalid URL, an SSL/TLS failure (`expired.badssl.com`) and result export. All passed. Performance tests measured about 1.2 s for a single scan and about 3.5 s for five concurrent scans.

## Project structure
```
Web-Security-Scanner/
├── app.py                # Flask web app
├── gui.py                # Tkinter desktop app
├── header_analysis.py    # header checks and scoring
├── requirements.txt
├── docs/
│   └── WebVulScannerReport.docx
└── README.md
```

## Tech stack
Python, Requests, Flask, Tkinter, SQLite

## Responsible use
This tool only reads the headers a server already sends in its normal responses. Only scan sites you own or have permission to test.

## Future work
Batch scanning, scheduled scans with email reports, richer dashboards, an API for developers, and more security checks.

## Author
Vrajkumar Patel
[LinkedIn](https://linkedin.com/in/vrajkumar-patel-9599b2227)
Vrajkumar Patel
[LinkedIn](https://linkedin.com/in/vrajkumar-patel-9599b2227)
