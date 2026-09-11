@echo off
echo Starting Phishing Detection Tool...
start cmd /k "cd backend && python app.py"
start cmd /k "cd frontend && npm start"
