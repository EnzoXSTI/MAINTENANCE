from flask import jsonify, request
from funcao import (senha_forte, verificar_existente, senha_correspondente,
                    gerar_token, decodificar_token, senha_ja_usada, salvar_historico_senha)
from flask_bcrypt import generate_password_hash, check_password_hash
from main import app
from db import conexao
import os
import datetime
import random
import smtplib
from email.mime.text import MIMEText


# ============================================================
# CRIAR USUÁRIO
# ============================================================
@app.route('/criar_usuarios', methods=['POST'])
def criar_usuarios():
    nome = request.form.get('nome', None)
    email = request.form.get('email', None)
    senha = request.form.get('senha')
    confirmar_senha = request.form.get('confirmar_senha')
    foto_perfil = request.files.get('foto_perfil')
    tipo = request.form.get('tipo', 1)

    try:
        tipo = int(tipo)
    except (ValueError, TypeError):
        tipo = 1

    data_cadastro = datetime.datetime.now()
    ativo = 1
    email_confirmacao = 0
    tentativa = 0

    con = conexao()
    cur = con.cursor()

    try:
        if not nome or nome.strip() == '':
            return jsonify({"error": "Nome é uma informação obrigatória."}), 400

        if not email or email.strip() == '':
            return jsonify({"error": "E-mail é uma informação obrigatória."}), 400

        if not verificar_existente(email):
            return jsonify({"error": "E-mail já cadastrado"}), 400

        if not senha_forte(senha):
            return jsonify({"error": "Senha fraca. A senha deve conter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."}), 400

        if not senha_correspondente(senha, confirmar_senha):
            return jsonify({"error": "Senhas não correspondem."}), 400

        senha_cripto = generate_password_hash(senha).decode('utf-8')

        # Gera código de verificação de email
        codigo_verificacao = random.randint(100000, 999999)

        cur.execute("""INSERT INTO USUARIOS (NOME, EMAIL, SENHA, TIPO, DATA_CADASTRO, ATIVO,
                                             EMAIL_CONFIRMACAO, CODIGO_VERIFICACAO, TENTATIVA)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING ID_USUARIO""",
                    (nome, email, senha_cripto, tipo, data_cadastro, ativo,
                     email_confirmacao, codigo_verificacao, tentativa))

        id_usuario = cur.fetchone()[0]

        salvar_historico_senha(id_usuario, senha_cripto, cur)

        con.commit()

        # Salva foto de perfil
        if foto_perfil:
            try:
                nome_imagem = f'{id_usuario}.jpeg'
                caminho_destino = os.path.join(app.config['UPLOAD_FOLDER'], 'Usuarios')
                os.makedirs(caminho_destino, exist_ok=True)
                foto_perfil.save(os.path.join(caminho_destino, nome_imagem))
            except Exception as e:
                print(f"ERRO ao salvar imagem: {e}")

        # Envia email de confirmação
        enviar_email_confirmacao(email, nome, codigo_verificacao)

        return jsonify({'message': "Usuário cadastrado com sucesso! Verifique seu e-mail para confirmar o cadastro."}), 201

    except Exception as e:
        print(f"ERRO ao cadastrar usuário: {e}")
        return jsonify({'error': f'Erro ao cadastrar usuário: {e}'}), 500
    finally:
        cur.close()
        con.close()


# ============================================================
# CONFIRMAR EMAIL
# ============================================================
@app.route('/confirmar_email', methods=['POST'])
def confirmar_email():
    email = request.form.get('email')
    codigo = request.form.get('codigo')

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("""SELECT ID_USUARIO, CODIGO_VERIFICACAO, EMAIL_CONFIRMACAO
                       FROM USUARIOS WHERE EMAIL = ?""", (email,))
        usuario = cur.fetchone()

        if not usuario:
            return jsonify({"error": "Usuário não encontrado"}), 404

        if usuario[2] == 1:
            return jsonify({"message": "E-mail já confirmado!"}), 200

        if str(usuario[1]) != str(codigo):
            return jsonify({"error": "Código inválido"}), 400

        cur.execute("""UPDATE USUARIOS SET EMAIL_CONFIRMACAO = 1, CODIGO_VERIFICACAO = 0
                       WHERE ID_USUARIO = ?""", (usuario[0],))
        con.commit()

        return jsonify({"message": "E-mail confirmado com sucesso!"}), 200

    except Exception as e:
        return jsonify({"error": f"Erro: {e}"}), 500
    finally:
        cur.close()
        con.close()


# ============================================================
# LOGIN
# ============================================================
@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    senha = request.form.get('senha')

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("""SELECT ID_USUARIO, NOME, EMAIL, SENHA, TIPO, ATIVO, EMAIL_CONFIRMACAO, TENTATIVA
                       FROM USUARIOS WHERE EMAIL = ?""", (email,))
        usuario = cur.fetchone()

        if not usuario:
            return jsonify({"error": "Usuário não encontrado"}), 404

        id_usuario  = usuario[0]
        nome        = usuario[1]
        email_db    = usuario[2]
        senha_hash  = usuario[3]
        tipo        = usuario[4]
        ativo       = usuario[5]
        confirmado  = usuario[6]
        tentativas  = usuario[7]

        if ativo == 0:
            return jsonify({"error": "Usuário bloqueado. Entre em contato com o administrador."}), 403

        if confirmado == 0:
            return jsonify({"error": "Confirme seu e-mail antes de logar!"}), 400

        if not check_password_hash(senha_hash, senha):
            # Incrementa tentativas
            nova_tentativa = tentativas + 1
            if nova_tentativa >= 3:
                # Bloqueia o usuário
                cur.execute("""UPDATE USUARIOS SET TENTATIVA = ?, ATIVO = 0
                               WHERE ID_USUARIO = ?""", (nova_tentativa, id_usuario))
                con.commit()
                return jsonify({"error": "Usuário bloqueado após 3 tentativas incorretas. Contate o administrador."}), 403
            else:
                cur.execute("""UPDATE USUARIOS SET TENTATIVA = ?
                               WHERE ID_USUARIO = ?""", (nova_tentativa, id_usuario))
                con.commit()
                return jsonify({"error": f"Senha incorreta. Tentativa {nova_tentativa} de 3."}), 400

        # Login OK — zera tentativas, gera token de 10 minutos
        cur.execute("UPDATE USUARIOS SET TENTATIVA = 0 WHERE ID_USUARIO = ?", (id_usuario,))
        con.commit()

        token = gerar_token(tipo, id_usuario, 10)

        return jsonify({
            'message': f'Bem-vindo {nome}!',
            'token': token,
            'usuario': {
                'id': id_usuario,
                'nome': nome,
                'email': email_db,
                'tipo': tipo
            }
        }), 200

    except Exception as e:
        return jsonify({'error': f'Erro ao fazer login: {e}'}), 500
    finally:
        cur.close()
        con.close()


# ============================================================
# LOGOUT
# ============================================================
@app.route('/logout', methods=['POST'])
def logout():
    # Com JWT stateless o logout é feito no front apagando o token
    # Aqui confirmamos o logout
    return jsonify({'message': 'Logout realizado com sucesso!'}), 200


# ============================================================
# RECUPERAR SENHA — ENVIAR CÓDIGO
# ============================================================
@app.route('/recuperar_senha', methods=['POST'])
def recuperar_senha():
    email = request.form.get('email')

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("SELECT ID_USUARIO, NOME FROM USUARIOS WHERE EMAIL = ?", (email,))
        usuario = cur.fetchone()

        if not usuario:
            return jsonify({"error": "E-mail não encontrado"}), 404

        codigo = random.randint(100000, 999999)

        cur.execute("UPDATE USUARIOS SET CODIGO_VERIFICACAO = ? WHERE ID_USUARIO = ?",
                    (codigo, usuario[0]))
        con.commit()

        enviar_email_recuperacao(email, usuario[1], codigo)

        return jsonify({"message": "Código de recuperação enviado para o seu e-mail!"}), 200

    except Exception as e:
        return jsonify({"error": f"Erro: {e}"}), 500
    finally:
        cur.close()
        con.close()


# ============================================================
# RECUPERAR SENHA — REDEFINIR
# ============================================================
@app.route('/redefinir_senha', methods=['POST'])
def redefinir_senha():
    email = request.form.get('email')
    codigo = request.form.get('codigo')
    nova_senha = request.form.get('nova_senha')
    confirmar_senha = request.form.get('confirmar_senha')

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("""SELECT ID_USUARIO, CODIGO_VERIFICACAO FROM USUARIOS
                       WHERE EMAIL = ?""", (email,))
        usuario = cur.fetchone()

        if not usuario:
            return jsonify({"error": "Usuário não encontrado"}), 404

        if str(usuario[1]) != str(codigo):
            return jsonify({"error": "Código inválido"}), 400

        if not senha_forte(nova_senha):
            return jsonify({"error": "Senha fraca. A senha deve conter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."}), 400

        if not senha_correspondente(nova_senha, confirmar_senha):
            return jsonify({"error": "Senhas não correspondem."}), 400

        # Verifica histórico das últimas 3 senhas
        if senha_ja_usada(usuario[0], nova_senha):
            return jsonify({"error": "Você não pode reutilizar uma das suas últimas 3 senhas."}), 400

        nova_senha_hash = generate_password_hash(nova_senha).decode('utf-8')

        cur.execute("""UPDATE USUARIOS SET SENHA = ?, CODIGO_VERIFICACAO = 0
                       WHERE ID_USUARIO = ?""", (nova_senha_hash, usuario[0]))

        salvar_historico_senha(usuario[0], nova_senha_hash, cur)
        con.commit()

        return jsonify({"message": "Senha redefinida com sucesso!"}), 200

    except Exception as e:
        return jsonify({"error": f"Erro: {e}"}), 500
    finally:
        cur.close()
        con.close()


# ============================================================
# EDITAR USUÁRIO
# ============================================================
@app.route('/editar_usuarios/<int:id_usuario>', methods=['PUT'])
def editar_usuarios(id_usuario):
    token_data = decodificar_token()

    if token_data == 'expirado':
        return jsonify({'error': 'Token expirado. Faça login novamente.'}), 401
    if not token_data:
        return jsonify({'error': 'Token necessário. Faça login primeiro.'}), 401
    if token_data['id_usuario'] != id_usuario and token_data['tipo'] != 0:
        return jsonify({'error': 'Você só pode editar seu próprio perfil.'}), 403

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("""SELECT ID_USUARIO, NOME, EMAIL, SENHA, TIPO
                       FROM USUARIOS WHERE ID_USUARIO = ?""", (id_usuario,))
        tem_usuario = cur.fetchone()

        if not tem_usuario:
            return jsonify({"error": "Usuário não encontrado"}), 404

        nome = request.form.get('nome', tem_usuario[1])
        email = request.form.get('email', tem_usuario[2])
        senha = request.form.get('senha', None)
        confirmar_senha = request.form.get('confirmar_senha', None)
        foto_perfil = request.files.get('foto_perfil')

        if not nome.strip():
            return jsonify({"error": "Nome é uma informação obrigatória."}), 400

        if not email.strip():
            return jsonify({"error": "E-mail é uma informação obrigatória."}), 400

        if email != tem_usuario[2] and not verificar_existente(email, id_usuario):
            return jsonify({"error": "E-mail já cadastrado"}), 400

        if senha:
            if not senha_forte(senha):
                return jsonify({"error": "Senha fraca. A senha deve conter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."}), 400

            if not senha_correspondente(senha, confirmar_senha):
                return jsonify({"error": "Senhas não correspondem."}), 400

            if senha_ja_usada(id_usuario, senha):
                return jsonify({"error": "Você não pode reutilizar uma das suas últimas 3 senhas."}), 400

            nova_senha_hash = generate_password_hash(senha).decode('utf-8')
            salvar_historico_senha(id_usuario, nova_senha_hash, cur)
        else:
            nova_senha_hash = tem_usuario[3]

        cur.execute("""UPDATE USUARIOS SET NOME = ?, EMAIL = ?, SENHA = ?
                       WHERE ID_USUARIO = ?""", (nome, email, nova_senha_hash, id_usuario))
        con.commit()

        if foto_perfil:
            try:
                nome_imagem = f'{id_usuario}.jpeg'
                caminho_destino = os.path.join(app.config['UPLOAD_FOLDER'], 'Usuarios')
                os.makedirs(caminho_destino, exist_ok=True)
                foto_perfil.save(os.path.join(caminho_destino, nome_imagem))
            except Exception as e:
                print(f"ERRO ao salvar imagem: {e}")

        return jsonify({
            'message': "Usuário editado com sucesso",
            'usuario': {'id': id_usuario, 'nome': nome, 'email': email}
        }), 200

    except Exception as e:
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


# ============================================================
# BUSCAR USUÁRIO
# ============================================================
@app.route('/buscar_usuarios/<int:id_usuario>', methods=['GET'])
def buscar_usuarios(id_usuario):
    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("""SELECT ID_USUARIO, NOME, EMAIL, TIPO, DATA_CADASTRO, ATIVO
                       FROM USUARIOS WHERE ID_USUARIO = ?""", (id_usuario,))
        usuario = cur.fetchone()

        if not usuario:
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
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


# ============================================================
# LISTAR USUÁRIOS
# ============================================================
@app.route('/listar_usuarios', methods=['GET'])
def listar_usuarios():
    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("""SELECT ID_USUARIO, NOME, EMAIL, TIPO, DATA_CADASTRO, ATIVO
                       FROM USUARIOS ORDER BY ID_USUARIO DESC""")
        usuarios = cur.fetchall()

        lista = [{
            'id': u[0], 'nome': u[1], 'email': u[2], 'tipo': u[3],
            'data_cadastro': u[4].strftime('%d/%m/%Y %H:%M:%S') if u[4] else None,
            'ativo': bool(u[5])
        } for u in usuarios]

        return jsonify({
            'message': 'Usuários listados com sucesso',
            'total': len(lista),
            'usuarios': lista
        }), 200

    except Exception as e:
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


# ============================================================
# DELETAR USUÁRIO
# ============================================================
@app.route('/deletar_usuarios/<int:id_usuario>', methods=['DELETE'])
def deletar_usuarios(id_usuario):
    token_data = decodificar_token()

    if token_data == 'expirado':
        return jsonify({'error': 'Token expirado.'}), 401
    if not token_data:
        return jsonify({'error': 'Token necessário.'}), 401
    if token_data['tipo'] != 0:
        return jsonify({'error': 'Apenas administradores podem deletar usuários.'}), 403

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("SELECT ID_USUARIO, NOME FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario,))
        usuario = cur.fetchone()

        if not usuario:
            return jsonify({"error": "Usuário não encontrado"}), 404

        caminho_foto = os.path.join(app.config['UPLOAD_FOLDER'], f'Usuarios/{id_usuario}.jpeg')
        if os.path.exists(caminho_foto):
            os.remove(caminho_foto)

        cur.execute("DELETE FROM HISTORICO_SENHAS WHERE ID_USUARIO = ?", (id_usuario,))
        cur.execute("DELETE FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario,))
        con.commit()

        return jsonify({'message': f"Usuário {usuario[1]} deletado com sucesso!", 'id': id_usuario}), 200

    except Exception as e:
        con.rollback()
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


# ============================================================
# DESBLOQUEAR USUÁRIO (somente ADM)
# ============================================================
@app.route('/desbloquear_usuario/<int:id_usuario>', methods=['PUT'])
def desbloquear_usuario(id_usuario):
    token_data = decodificar_token()

    if token_data == 'expirado':
        return jsonify({'error': 'Token expirado.'}), 401
    if not token_data:
        return jsonify({'error': 'Token necessário.'}), 401
    if token_data['tipo'] != 0:
        return jsonify({'error': 'Apenas administradores podem desbloquear usuários.'}), 403

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("SELECT ID_USUARIO FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario,))
        if not cur.fetchone():
            return jsonify({"error": "Usuário não encontrado"}), 404

        cur.execute("UPDATE USUARIOS SET ATIVO = 1, TENTATIVA = 0 WHERE ID_USUARIO = ?", (id_usuario,))
        con.commit()

        return jsonify({"message": "Usuário desbloqueado com sucesso!"}), 200

    except Exception as e:
        return jsonify({"error": f"Erro: {e}"}), 500
    finally:
        cur.close()
        con.close()


# ============================================================
# FUNÇÕES DE EMAIL
# ============================================================
def enviar_email_confirmacao(email, nome, codigo):
    try:
        msg = MIMEText(f'Olá {nome},\n\nSeu código de confirmação é: {codigo}\n\nMaintenance System')
        msg['Subject'] = 'Confirmação de E-mail - Maintenance'
        msg['From'] = app.config.get('EMAIL_REMETENTE', 'noreply@maintenance.com')
        msg['To'] = email

        with smtplib.SMTP(app.config.get('EMAIL_HOST', 'smtp.gmail.com'),
                          app.config.get('EMAIL_PORT', 587)) as server:
            server.starttls()
            server.login(app.config.get('EMAIL_REMETENTE'), app.config.get('EMAIL_SENHA'))
            server.send_message(msg)
    except Exception as e:
        print(f"ERRO ao enviar email de confirmação: {e}")


def enviar_email_recuperacao(email, nome, codigo):
    try:
        msg = MIMEText(f'Olá {nome},\n\nSeu código de recuperação de senha é: {codigo}\n\nMaintenance System')
        msg['Subject'] = 'Recuperação de Senha - Maintenance'
        msg['From'] = app.config.get('EMAIL_REMETENTE', 'noreply@maintenance.com')
        msg['To'] = email

        with smtplib.SMTP(app.config.get('EMAIL_HOST', 'smtp.gmail.com'),
                          app.config.get('EMAIL_PORT', 587)) as server:
            server.starttls()
            server.login(app.config.get('EMAIL_REMETENTE'), app.config.get('EMAIL_SENHA'))
            server.send_message(msg)
    except Exception as e:
        print(f"ERRO ao enviar email de recuperação: {e}")
