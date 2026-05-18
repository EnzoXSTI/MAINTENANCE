from flask import Flask, send_from_directory
from flask_cors import CORS
import os

app = Flask(__name__)

CORS(app,
     origins=["http://localhost:5173", "http://10.92.3.117:5000"],
     supports_credentials=True
)

app.config.from_pyfile('config.py')

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
os.makedirs(os.path.join(app.config['UPLOAD_FOLDER'], 'Usuarios'), exist_ok=True)


@app.route('/uploads/<path:filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

from usuario import *

if __name__ == '__main__':
    print("\n=== ROTAS REGISTRADAS ===")
    for rule in app.url_map.iter_rules():
        if not rule.rule.startswith('/static'):
            print(f"{list(rule.methods)} {rule.rule}")
    print("=========================\n")
    app.run(host='0.0.0.0', port=5000, debug=True)