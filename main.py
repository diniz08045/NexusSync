from app import create_app

# Create the Flask application instance using the factory method
app = create_app()

# Entry point for running the app directly
if __name__ == "__main__":
    # Start the development server on localhost at port 5000 with debug mode enabled.
    # In production, use a proper WSGI server like Gunicorn or uWSGI instead.
    app.run(host="127.0.0.1", port=5000, debug=True)
