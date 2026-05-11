from flask import Flask, send_from_directory, make_response, request
from flask_cors import CORS
import os

app = Flask(__name__)

# 1. Configuração de CORS Robusta (Igual à base de apoio)
# Permite que o front-end envie cookies e tokens com segurança
CORS(app,
     origins=["http://localhost:5173", "http://127.0.0.1:5173"],
     methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
     allow_headers=["Content-Type", "Authorization", "Access-Control-Allow-Credentials"],
     supports_credentials=True
)

# 2. Tratamento Manual de OPTIONS (Evita erros de Preflight no Navegador)
@app.before_request
def handle_options():
    if request.method == 'OPTIONS':
        response = make_response()
        origin = request.headers.get('Origin')
        response.headers['Access-Control-Allow-Origin'] = origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response, 200

# 3. Carregamento de Configurações
app.config.from_pyfile('config.py')

# 4. Gestão Automática de Pastas de Upload
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
# Define a pasta de upload dentro do projeto
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'upload')

# Cria as pastas caso elas não existam (evita erro ao salvar fotos)
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
    print(f"Pasta de uploads criada em: {app.config['UPLOAD_FOLDER']}")

# 5. Rota para Servir as Imagens Salvas
@app.route('/upload/<path:filename>')
def servir_upload(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# 6. Importação das tuas rotas (View)
from view import *

if __name__ == '__main__':
    # Rodando em 0.0.0.0 para ser acessível na rede local
    app.run(host='0.0.0.0', port=5000, debug=True)