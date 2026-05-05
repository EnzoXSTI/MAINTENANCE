from flask import jsonify, request
from funcao import senha_forte, verificar_existente, senha_correspondente
from flask_bcrypt import generate_password_hash, check_password_hash
from main import app
from db import conexao
import os
import datetime


@app.route('/criar_usuarios', methods=['POST'])
def criar_usuarios():
    nome = request.form.get('nome', None)
    email = request.form.get('email', None)
    senha = request.form.get('senha')
    confirmar_senha = request.form.get('confirmar_senha')
    foto_perfil = request.files.get('foto_perfil')

    # Tipo 0 - ADM | Tipo 1 - professor | Tipo 2 - tecnico
    tipo = request.form.get('tipo', 1)

    try:
        tipo = int(tipo)
    except (ValueError, TypeError):
        tipo = 1

    data_cadastro = datetime.datetime.now()
    ativo = 1
    email_confirmacao = 0
    codigo_verificacao = 0
    tentativa = 0

    con = conexao()
    cur = con.cursor()

    try:
        if nome == None or nome.strip() == '':
            return jsonify({"error": "Nome é uma informação obrigatória."}), 400

        if email == None or email.strip() == '':
            return jsonify({"error": "E-mail é uma informação obrigatória."}), 400

        if verificar_existente(email) == False:
            return jsonify({"error": "E-mail já cadastrado"}), 400

        if senha_forte(senha) == False:
            return jsonify({
                "error": "Senha fraca. A senha deve conter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."
            }), 400

        if senha_correspondente(senha, confirmar_senha) == False:
            return jsonify({"error": "Senhas não correspondem."}), 400

        senha_cripto = generate_password_hash(senha).decode('utf-8')

        cur.execute("""INSERT INTO USUARIOS (NOME, EMAIL, SENHA, TIPO, DATA_CADASTRO, ATIVO, 
                                             EMAIL_CONFIRMACAO, CODIGO_VERIFICACAO, TENTATIVA)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING ID_USUARIO""",
                    (nome, email, senha_cripto, tipo, data_cadastro, ativo,
                     email_confirmacao, codigo_verificacao, tentativa))  # <<<<<< TENTATIVA ADICIONADO

        id_usuario = cur.fetchone()[0]
        con.commit()

        if foto_perfil:
            try:
                nome_imagem = f'{id_usuario}.jpeg'
                caminho_imagem_destino = os.path.join(app.config['UPLOAD_FOLDER'], 'Usuarios')
                os.makedirs(caminho_imagem_destino, exist_ok=True)
                caminho_imagem = os.path.join(caminho_imagem_destino, nome_imagem)
                foto_perfil.save(caminho_imagem)
            except Exception as e:
                print(f"ERRO ao salvar imagem: {e}")

        return jsonify({
            'message': "Usuário cadastrado com sucesso"}), 201

    except Exception as e:
        print(f"ERRO ao cadastrar usuário: {e}")
        return jsonify({'message': f'Erro ao consultar o banco de dados: {e}'}), 500
    finally:
        cur.close()
        con.close()


# Login
@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    senha = request.form.get('senha')

    con = conexao()
    cur = con.cursor()

    try:
        # Busca o usuário pelo email
        cur.execute("""SELECT ID_USUARIO, NOME, EMAIL, SENHA, TIPO, ATIVO, EMAIL_CONFIRMACAO
                       FROM USUARIOS
                       WHERE EMAIL = ?""", (email,))

        usuario = cur.fetchone()

        if not usuario:
            return jsonify({"error": "Usuário não encontrado"}), 404

        id_usuario = usuario[0]
        nome = usuario[1]
        email_usuario = usuario[2]
        senha_hash = usuario[3]
        tipo = usuario[4]
        ativo = usuario[5]
        email_confirmado = usuario[6]

        # Verifica se está ativo
        if ativo == 0:
            return jsonify({"error": "Usuário inativado"}), 400

        # Verifica se email foi confirmado
        if email_confirmado == 0:
            return jsonify({"error": "Confirme seu e-mail antes de logar!"}), 400

        # Verifica a senha
        if check_password_hash(senha_hash, senha):
            # Gera token com validade de 60 minutos
            token = gerar_token(tipo, id_usuario, 60)

            return jsonify({
                'message': f'Bem-vindo {nome}!',
                'token': token,
                'usuario': {
                    'id': id_usuario,
                    'nome': nome,
                    'email': email_usuario,
                    'tipo': tipo
                }
            }), 200

        return jsonify({"error": "Senha incorreta"}), 400

    except Exception as e:
        return jsonify({'error': f'Erro ao fazer login: {e}'}), 500
    finally:
        cur.close()
        con.close()


# Editar usuário (com validação de token)
@app.route('/editar_usuarios/<int:id_usuario>', methods=['PUT'])
def editar_usuarios(id_usuario):
    # ========== VALIDAÇÃO DE TOKEN ==========
    token_data = decodificar_token()

    if token_data == False:
        return jsonify({'error': 'Token necessário. Faça login primeiro.'}), 401

    # Verifica se o usuário só pode editar a si mesmo (ou é admin)
    if token_data['id_usuario'] != id_usuario and token_data['tipo'] != 0:
        return jsonify({'error': 'Você só pode editar seu próprio perfil.'}), 403

    # Cria a conexão com o banco
    con = conexao()
    cur = con.cursor()

    try:
        # Busca os dados atuais do usuário
        cur.execute("""SELECT ID_USUARIO, NOME, EMAIL, SENHA, TIPO
                       FROM USUARIOS
                       WHERE ID_USUARIO = ?""", (id_usuario,))

        tem_usuario = cur.fetchone()

        if tem_usuario == None:
            return jsonify({"error": "Usuário não encontrado"}), 404

        # Pega os dados enviados ou mantém os atuais
        nome = request.form.get('nome', tem_usuario[1])
        email = request.form.get('email', tem_usuario[2])
        senha = request.form.get('senha', None)
        confirmar_senha = request.form.get('confirmar_senha', None)
        foto_perfil = request.files.get('foto_perfil')

        # Verifica se o nome está vazio
        nome_sem_espacos = nome.strip()
        if nome_sem_espacos == '':
            return jsonify({"error": "Nome é uma informação obrigatória."}), 400

        # Verifica se o email está vazio
        email_sem_espacos = email.strip()
        if email_sem_espacos == '':
            return jsonify({"error": "E-mail é uma informação obrigatória."}), 400

        # Verifica se email já existe (exceto o próprio usuário)
        if email != tem_usuario[2]:
            if verificar_existente(email, id_usuario) == False:
                return jsonify({"error": "E-mail já cadastrado"}), 400

        # Verifica se foi enviada uma nova senha
        if senha != None:
            if senha_forte(senha) == False:
                return jsonify({
                    "error": "Senha fraca. A senha deve conter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."
                }), 400

            if senha_correspondente(senha, confirmar_senha) == False:
                return jsonify({"error": "Senhas não correspondem."}), 400

            nova_senha_hash = generate_password_hash(senha).decode('utf-8')
        else:
            nova_senha_hash = tem_usuario[3]

        # Atualiza os dados do usuário no banco
        cur.execute("""UPDATE USUARIOS
                       SET NOME  = ?,
                           EMAIL = ?,
                           SENHA = ?
                       WHERE ID_USUARIO = ?""", (nome, email, nova_senha_hash, id_usuario))

        con.commit()

        # Verifica se foi enviada uma nova foto
        if foto_perfil:
            try:
                nome_imagem = f'{id_usuario}.jpeg'
                caminho_imagem_destino = os.path.join(app.config['UPLOAD_FOLDER'], 'Usuarios')
                os.makedirs(caminho_imagem_destino, exist_ok=True)
                caminho_imagem = os.path.join(caminho_imagem_destino, nome_imagem)
                foto_perfil.save(caminho_imagem)
            except Exception as e:
                print(f"ERRO ao salvar imagem: {e}")

        return jsonify({
            'message': "Usuário editado com sucesso",
            'usuario': {
                'id': id_usuario,
                'nome': nome,
                'email': email
            }
        }), 201

    except Exception as e:
        return jsonify({'message': f'Erro ao consultar o banco de dados: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/buscar_usuarios/<int:id_usuario>', methods=['GET'])
def buscar_usuarios(id_usuario):

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("""SELECT ID_USUARIO,
                              NOME,
                              EMAIL,
                              TIPO,
                              DATA_CADASTRO,
                              ATIVO
                       FROM USUARIOS
                       WHERE ID_USUARIO = ?""", (id_usuario,))

        usuario = cur.fetchone()

        if usuario == None:
            return jsonify({"error": "Usuário não encontrado"}), 404

        return jsonify({
            'message': "Usuário encontrado",
            'usuario': {
                'id': usuario[0],
                'nome': usuario[1],
                'email': usuario[2],
                'tipo': usuario[3],
                'data_cadastro': usuario[4].strftime('%d/%m/%Y %H:%M:%S') if usuario[4] else None,
                'ativo': bool(usuario[5])
            }
        }), 200

    except Exception as e:
        return jsonify({'message': f'Erro ao consultar o banco de dados: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/listar_usuarios', methods=['GET'])
def listar_usuarios():

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("""SELECT ID_USUARIO,
                              NOME,
                              EMAIL,
                              TIPO,
                              DATA_CADASTRO,
                              ATIVO
                       FROM USUARIOS
                       ORDER BY ID_USUARIO DESC""")

        usuarios = cur.fetchall()

        if usuarios:
            lista_usuarios = []
            for u in usuarios:
                lista_usuarios.append({
                    'id': u[0],
                    'nome': u[1],
                    'email': u[2],
                    'tipo': u[3],
                    'data_cadastro': u[4].strftime('%d/%m/%Y %H:%M:%S') if u[4] else None,
                    'ativo': bool(u[5])
                })

            return jsonify({
                'message': 'Usuários listados com sucesso',
                'total': len(lista_usuarios),
                'usuarios': lista_usuarios
            }), 200
        else:
            return jsonify({
                'message': 'Nenhum usuário cadastrado',
                'usuarios': []
            }), 200

    except Exception as e:
        return jsonify({'message': f'Erro ao consultar o banco de dados: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/deletar_usuarios/<int:id_usuario>', methods=['DELETE'])
def deletar_usuarios(id_usuario):

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("""SELECT ID_USUARIO, NOME
                       FROM USUARIOS
                       WHERE ID_USUARIO = ?""", (id_usuario,))

        usuario = cur.fetchone()

        if usuario == None:
            return jsonify({"error": "Usuário não encontrado"}), 404

        caminho_foto = os.path.join(app.config['UPLOAD_FOLDER'], f'Usuarios/{id_usuario}.jpeg')
        if os.path.exists(caminho_foto):
            os.remove(caminho_foto)

        cur.execute("""DELETE
                       FROM USUARIOS
                       WHERE ID_USUARIO = ?""", (id_usuario,))

        con.commit()

        return jsonify({
            'message': f"Usuário {usuario[1]} deletado com sucesso!",
            'id': id_usuario
        }), 200

    except Exception as e:
        con.rollback()
        return jsonify({'message': f'Erro ao consultar o banco de dados: {e}'}), 500
    finally:
        cur.close()
        con.close()