from app import app
import logging
from datetime import datetime
from flask import render_template
from flask_login import current_user

# Add current date/time to all templates
@app.context_processor
def inject_now():
    return {'now': datetime.utcnow()}
    
@app.route('/debug')
def debug():
    """Debug page with minimal dependencies."""
    username = current_user.username if current_user.is_authenticated else 'Not logged in'
    return render_template('debug.html', 
                          current_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                          username=username)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    app.run(host="0.0.0.0", port=5000, debug=True)
