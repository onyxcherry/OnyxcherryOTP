#!/bin/bash
source venv/bin/activate
flask translate compile
exec gunicorn -b :5777 --access-logfile - --error-logfile - onyxcherryotp:app
