from app import app
import logging
from datetime import datetime

# Add current date/time to all templates
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    app.run(host="0.0.0.0", port=5000, debug=True)
