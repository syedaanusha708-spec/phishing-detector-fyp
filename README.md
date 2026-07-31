# Phishing Website Detection Tool — FYP-I Skeleton

A working skeleton of the project shown in the presentation: a React frontend
talking to a Flask backend that runs a Random Forest model on 8 URL features.
This is intentionally kept simple (skeleton) so you can extend it for FYP-II.

## Project structure

```
phishing-detector/
├── backend/
│   ├── app.py                 # Flask API: /scan, /scan-email, /health
│   ├── feature_extraction.py  # extracts the 8 URL features
│   ├── requirements.txt
│   └── model/
│       ├── dataset.csv        # sample labeled URLs (expand this later!)
│       ├── train_model.py     # trains and saves model.pkl
│       └── model.pkl          # created after you run train_model.py
└── frontend/
    ├── index.html
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── main.jsx
        ├── App.jsx            # URL scanner + Email scanner UI
        ├── api.js              # all backend fetch calls live here
        └── index.css
```

## How to run it in VS Code

**1. Backend (Flask)**
```bash
cd backend
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux
pip install -r requirements.txt
python model/train_model.py   # trains model, creates model.pkl (run once)
python app.py                 # starts API at http://localhost:5000
```

**2. Frontend (React + Vite)** — open a second terminal
```bash
cd frontend
npm install
npm run dev                   # starts UI at http://localhost:3000
```

Open `http://localhost:3000` in your browser — you should see the scanner UI
talking to your Flask API.

## Dataset note

`dataset.csv` currently has ~30 sample URLs so the model trains instantly for
demo purposes. For FYP-II, replace/expand it with real data from PhishTank
and Kaggle (your presentation already mentions this — aim for hundreds of
labeled URLs for a more convincing accuracy report).

## Where to add new features later

- **New URL-based signals** (domain age, SSL check, typosquatting, VirusTotal):
  add a function in `backend/feature_extraction.py` or a new module, then call
  it inside the `/scan` route in `app.py` (there's a comment marking where).
- **New API calls**: add them to `frontend/src/api.js`.
- **New pages/tabs** (Bulk Scanner, Stats Dashboard, Login, PDF export, Dark
  Mode toggle): add a new tab button + component in `frontend/src/App.jsx`,
  following the pattern of `UrlScanner` / `EmailScanner`.

## Tech stack

- **Backend:** Python, Flask, Flask-CORS, scikit-learn, pandas, joblib
- **Frontend:** React 18, Vite
- **Model:** Random Forest Classifier (8 URL-based features)
