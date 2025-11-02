from app import app, start_eod_scheduler

# Initialize EOD scheduler for production (gunicorn)
start_eod_scheduler(app)

# Ensure all routes are imported and registered
import sys
print(f"Flask app routes: {[rule.rule for rule in app.url_map.iter_rules()]}", file=sys.stderr)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
