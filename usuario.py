from flask import jsonify, request, make_response
from flask_bcrypt import generate_password_hash, check_password_hash
from main import app
from db import conexao
from funcao import senha_forte, verificar_existente, senha_correspondente, senha_antiga, gerar_token, decodificar_token, enviando_email, renderizar_template
import os
import datetime
from random import randint
import threading


@app.route('/criar_usuarios', methods=['POST'])
def criar_usuarios():
    nome          = request.form.get('nome', None)
    email         = request.form.get('email', None)
    senha         = request.form.get('senha')
    confirmar     = request.form.get('confirmar_senha')
    foto_perfil   = request.files.get('foto_perfil')
    tipo          = request.form.get('tipo', 1)

    try:
        tipo = int(tipo)
    except:
        tipo = 1

    con = conexao()
    cur = con.cursor()

    try:
        if not nome or nome.strip() == '':
            return jsonify({"error": "Nome é obrigatório"}), 400
        if not email or email.strip() == '':
            return jsonify({"error": "E-mail é obrigatório"}), 400
        if not verificar_existente(email):
            return jsonify({"error": "E-mail já cadastrado"}), 400
        if not senha_forte(senha):
            return jsonify({"error": "Senha fraca. Use pelo menos 8 caracteres com maiúsculas, minúsculas, números e caracteres especiais."}), 400
        if not senha_correspondente(senha, confirmar):
            return jsonify({"error": "Senhas não correspondem"}), 400

        senha_cripto       = generate_password_hash(senha).decode('utf-8')
        codigo_confirmacao = str(randint(100000, 999999))
        data_cadastro      = datetime.datetime.now()

        cur.execute("""INSERT INTO USUARIOS (NOME, EMAIL, SENHA, TIPO, DATA_CADASTRO,
                                             ATIVO, EMAIL_CONFIRMACAO, CODIGO_VERIFICACAO, TENTATIVA)
                       VALUES (?, ?, ?, ?, ?, 1, 0, ?, 0) RETURNING ID_USUARIO""",
                    (nome, email, senha_cripto, tipo, data_cadastro, codigo_confirmacao))

        id_usuario = cur.fetchone()[0]
        con.commit()

        if foto_perfil:
            try:
                caminho = os.path.join(app.config['UPLOAD_FOLDER'], 'Usuarios', f'{id_usuario}.jpeg')
                foto_perfil.save(caminho)
            except Exception as e:
                print(f"Erro ao salvar foto: {e}")

        email_user  = app.config.get('EMAIL_REMETENTE', '')
        email_senha = app.config.get('EMAIL_SENHA', '')
        assunto  = 'Confirmação de E-mail - Maintenance'
        mensagem = f'Olá {nome}! Seu código de confirmação é: {codigo_confirmacao}. Válido por 10 minutos.'
        html = renderizar_template(
            os.path.join(os.path.dirname(__file__), 'templates', 'email_codigo.html'),
            {
                'assunto':   'Confirmação de E-mail',
                'titulo':    'Confirme seu cadastro',
                'subtitulo': 'Você está a um passo de acessar o sistema.',
                'nome':      nome,
                'mensagem':  'Para ativar sua conta, utilize o código de verificação abaixo:',
                'codigo':    codigo_confirmacao,
                'validade':  '10 minutos',
            }
        )
        threading.Thread(target=enviando_email, args=(email, assunto, mensagem, email_user, email_senha, html)).start()

        return jsonify({'message': "Usuário cadastrado! Verifique seu e-mail para confirmar o cadastro."}), 201

    except Exception as e:
        print(f"Erro: {e}")
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/confirmar_email', methods=['POST'])
def confirmar_email():
    email  = request.form.get('email')
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

        id_usuario = usuario[0]
        nome       = usuario[1]
        email_db   = usuario[2]
        senha_hash = usuario[3]
        tipo       = usuario[4]
        ativo      = usuario[5]
        confirmado = usuario[6]
        tentativas = usuario[7]

        if ativo == 0:
            return jsonify({"error": "Usuário bloqueado. Entre em contato com o administrador."}), 403

        if confirmado == 0:
            return jsonify({"error": "Confirme seu e-mail antes de logar!"}), 400

        if not check_password_hash(senha_hash, senha):
            nova_tentativa = tentativas + 1

            if nova_tentativa >= 3 and tipo != 0:
                cur.execute("UPDATE USUARIOS SET TENTATIVA = ?, ATIVO = 0 WHERE ID_USUARIO = ?",
                            (nova_tentativa, id_usuario))
                con.commit()
                return jsonify(
                    {"error": "Usuário bloqueado após 3 tentativas incorretas. Contate o administrador."}), 403

            cur.execute("UPDATE USUARIOS SET TENTATIVA = ? WHERE ID_USUARIO = ?",
                        (nova_tentativa, id_usuario))
            con.commit()
            return jsonify({"error": "Senha incorreta."}), 400

        cur.execute("UPDATE USUARIOS SET TENTATIVA = 0 WHERE ID_USUARIO = ?", (id_usuario,))
        con.commit()

        token = gerar_token(tipo, id_usuario, 10)

        resp = make_response(jsonify({
            'message': f'Bem-vindo {nome}!',
            'token': token,
            'usuario': {'id': id_usuario, 'nome': nome, 'email': email_db, 'tipo': tipo}
        }), 200)

        resp.set_cookie('acess_token', token, httponly=True, secure=False,
                        samesite='Lax', path='/', max_age=600)

        return resp

    except Exception as e:
        return jsonify({'error': f'Erro ao fazer login: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/logout', methods=['POST'])
def logout():
    resp = make_response(jsonify({'message': 'Logout realizado com sucesso!'}), 200)
    resp.delete_cookie('acess_token')
    return resp


@app.route('/esqueci_senha', methods=['POST'])
def esqueci_senha():
    email = request.form.get('email')

    if not email:
        return jsonify({'error': 'Informe o e-mail'}), 400

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("SELECT ID_USUARIO, NOME, ATIVO FROM USUARIOS WHERE EMAIL = ?", (email,))
        usuario = cur.fetchone()

        if not usuario:
            return jsonify({'error': 'Usuário não encontrado'}), 404
        if usuario[2] == 0:
            return jsonify({'error': 'Usuário bloqueado'}), 403

        codigo  = randint(100000, 999999)
        cur.execute("UPDATE USUARIOS SET CODIGO_VERIFICACAO = ? WHERE ID_USUARIO = ?",
                    (codigo, usuario[0]))
        con.commit()

        email_user  = app.config.get('EMAIL_REMETENTE', '')
        email_senha = app.config.get('EMAIL_SENHA', '')
        assunto  = 'Recuperação de Senha - Maintenance'
        mensagem = f'Olá {usuario[1]}! Seu código de recuperação é: {codigo}.'
        html = renderizar_template(
            os.path.join(os.path.dirname(__file__), 'templates', 'email_codigo.html'),
            {
                'assunto':   'Recuperação de Senha',
                'titulo':    'Redefinição de senha',
                'subtitulo': 'Recebemos uma solicitação para redefinir sua senha.',
                'nome':      usuario[1],
                'mensagem':  'Use o código abaixo para criar uma nova senha. Se não foi você, ignore este e-mail.',
                'codigo':    str(codigo),
                'validade':  '5 minutos',
            }
        )
        threading.Thread(target=enviando_email, args=(email, assunto, mensagem, email_user, email_senha, html)).start()

        return jsonify({'message': 'Código enviado para o e-mail!'}), 200

    except Exception as e:
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/verificar_codigo', methods=['POST'])
def verificar_codigo():
    email  = request.form.get('email')
    codigo = request.form.get('codigo')

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("""SELECT ID_USUARIO, TIPO, CODIGO_VERIFICACAO
                       FROM USUARIOS WHERE EMAIL = ?""", (email,))
        usuario = cur.fetchone()

        if not usuario:
            return jsonify({'error': 'Usuário não encontrado'}), 404
        if str(usuario[2]) != str(codigo):
            return jsonify({'error': 'Código inválido!'}), 400

        token = gerar_token(usuario[1], usuario[0], 5)

        return jsonify({
            'message': 'Código correto! Você tem 5 minutos para redefinir sua senha.',
            'token': token
        }), 200

    except Exception as e:
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/redefinir_senha', methods=['POST'])
def redefinir_senha():
    token_data = decodificar_token()
    if not token_data:
        return jsonify({'error': 'Token necessário'}), 401

    nova_senha = request.form.get('nova_senha')
    confirmar  = request.form.get('confirmar_senha')
    id_usuario = token_data['id_usuario']

    if not senha_forte(nova_senha):
        return jsonify({"error": "Senha fraca. Use pelo menos 8 caracteres com maiúsculas, minúsculas, números e caracteres especiais."}), 400
    if not senha_correspondente(nova_senha, confirmar):
        return jsonify({"error": "Senhas não correspondem"}), 400
    if not senha_antiga(id_usuario, nova_senha):
        return jsonify({"error": "Você não pode reutilizar uma das suas últimas 3 senhas."}), 400

    con = conexao()
    cur = con.cursor()

    try:
        nova_hash = generate_password_hash(nova_senha).decode('utf-8')
        cur.execute("""UPDATE USUARIOS SET SENHA = ?, CODIGO_VERIFICACAO = 0
                       WHERE ID_USUARIO = ?""", (nova_hash, id_usuario))
        con.commit()

        return jsonify({"message": "Senha redefinida com sucesso!"}), 200

    except Exception as e:
        return jsonify({"error": f"Erro: {e}"}), 500
    finally:
        cur.close()
        con.close()


@app.route('/editar_usuarios/<int:id_usuario>', methods=['PUT'])
def editar_usuarios(id_usuario):
    token_data = decodificar_token()
    if not token_data:
        return jsonify({'error': 'Token necessário'}), 401
    if token_data['id_usuario'] != id_usuario and token_data['tipo'] != 0:
        return jsonify({'error': 'Você só pode editar seu próprio perfil'}), 403

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("SELECT ID_USUARIO, NOME, EMAIL, SENHA FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario,))
        usuario = cur.fetchone()

        if not usuario:
            return jsonify({"error": "Usuário não encontrado"}), 404

        nome          = request.form.get('nome', usuario[1])
        email         = request.form.get('email', usuario[2])
        senha         = request.form.get('senha', None)
        confirmar     = request.form.get('confirmar_senha', None)
        foto_perfil   = request.files.get('foto_perfil')

        if not nome.strip():
            return jsonify({"error": "Nome é obrigatório"}), 400
        if not email.strip():
            return jsonify({"error": "E-mail é obrigatório"}), 400
        if email != usuario[2] and not verificar_existente(email, id_usuario):
            return jsonify({"error": "E-mail já cadastrado"}), 400

        if senha:
            if not senha_forte(senha):
                return jsonify({"error": "Senha fraca. Use pelo menos 8 caracteres com maiúsculas, minúsculas, números e caracteres especiais."}), 400
            if not senha_correspondente(senha, confirmar):
                return jsonify({"error": "Senhas não correspondem"}), 400
            if not senha_antiga(id_usuario, senha):
                return jsonify({"error": "Você não pode reutilizar uma das suas últimas 3 senhas."}), 400
            nova_hash = generate_password_hash(senha).decode('utf-8')
        else:
            nova_hash = usuario[3]

        email_mudou = email != usuario[2]

        if email_mudou:
            codigo_confirmacao = str(randint(100000, 999999))
            cur.execute('UPDATE USUARIOS SET NOME = ?, EMAIL = ?, SENHA = ?, EMAIL_CONFIRMACAO = 0, CODIGO_VERIFICACAO = ? WHERE ID_USUARIO = ?',
                        (nome, email, nova_hash, codigo_confirmacao, id_usuario))
        else:
            cur.execute('UPDATE USUARIOS SET NOME = ?, EMAIL = ?, SENHA = ? WHERE ID_USUARIO = ?',
                        (nome, email, nova_hash, id_usuario))
        con.commit()

        if foto_perfil:
            try:
                caminho = os.path.join(app.config['UPLOAD_FOLDER'], 'Usuarios', f'{id_usuario}.jpeg')
                foto_perfil.save(caminho)
            except Exception as e:
                print(f'Erro ao salvar foto: {e}')

        if email_mudou:
            email_user  = app.config.get('EMAIL_REMETENTE', '')
            email_senha = app.config.get('EMAIL_SENHA', '')
            assunto  = 'Confirmacao de E-mail - Maintenance'
            mensagem_email = f'Ola {nome}! Seu codigo de confirmacao e: {codigo_confirmacao}.'
            html = renderizar_template(
                os.path.join(os.path.dirname(__file__), 'templates', 'email_codigo.html'),
                {
                    'assunto':   'Confirmacao de E-mail',
                    'titulo':    'Confirme seu novo e-mail',
                    'subtitulo': 'Seu e-mail foi alterado.',
                    'nome':      nome,
                    'mensagem':  'Para confirmar o novo e-mail, utilize o codigo abaixo:',
                    'codigo':    codigo_confirmacao,
                    'validade':  '10 minutos',
                }
            )
            threading.Thread(target=enviando_email, args=(email, assunto, mensagem_email, email_user, email_senha, html)).start()
            return jsonify({'message': 'Usuario editado! Confirme o novo e-mail.', 'email_mudou': True,
                            'usuario': {'id': id_usuario, 'nome': nome, 'email': email}}), 200

        return jsonify({'message': 'Usuario editado com sucesso!', 'email_mudou': False,
                        'usuario': {'id': id_usuario, 'nome': nome, 'email': email}}), 200

    except Exception as e:
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


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

        return jsonify({'usuario': {
            'id': usuario[0], 'nome': usuario[1], 'email': usuario[2], 'tipo': usuario[3],
            'data_cadastro': usuario[4].strftime('%d/%m/%Y %H:%M:%S') if usuario[4] else None,
            'ativo': bool(usuario[5])
        }}), 200

    except Exception as e:
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/listar_usuarios', methods=['GET'])
def listar_usuarios():
    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("""SELECT ID_USUARIO, NOME, EMAIL, TIPO, DATA_CADASTRO, ATIVO
                       FROM USUARIOS ORDER BY ID_USUARIO DESC""")
        usuarios = cur.fetchall()

        lista = [{'id': u[0], 'nome': u[1], 'email': u[2], 'tipo': u[3],
                  'data_cadastro': u[4].strftime('%d/%m/%Y %H:%M:%S') if u[4] else None,
                  'ativo': bool(u[5])} for u in usuarios]

        return jsonify({'total': len(lista), 'usuarios': lista}), 200

    except Exception as e:
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/deletar_usuarios/<int:id_usuario>', methods=['DELETE'])
def deletar_usuarios(id_usuario):
    token_data = decodificar_token()
    if not token_data:
        return jsonify({'error': 'Token necessário'}), 401
    if token_data['tipo'] != 0:
        return jsonify({'error': 'Apenas administradores podem deletar usuários'}), 403

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("SELECT ID_USUARIO, NOME FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario,))
        usuario = cur.fetchone()

        if not usuario:
            return jsonify({"error": "Usuário não encontrado"}), 404

        # Remove foto
        caminho_foto = os.path.join(app.config['UPLOAD_FOLDER'], 'Usuarios', f'{id_usuario}.jpeg')
        if os.path.exists(caminho_foto):
            os.remove(caminho_foto)

        cur.execute("DELETE FROM HISTORICO_SENHA WHERE ID_USUARIO = ?", (id_usuario,))
        cur.execute("DELETE FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario,))
        con.commit()

        return jsonify({'message': f"Usuário {usuario[1]} deletado com sucesso!"}), 200

    except Exception as e:
        con.rollback()
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()

@app.route('/bloquear_usuario/<int:id_usuario>', methods=['PUT'])
def bloquear_usuario(id_usuario):
    dados = decodificar_token()
    if not dados or dados['tipo'] != 0:
        return jsonify({'error': 'Acesso negado.'}), 403
    con = conexao()
    cur = con.cursor()
    try:
        cur.execute("UPDATE USUARIOS SET ATIVO = 0 WHERE ID_USUARIO = ?", (id_usuario,))
        con.commit()
        return jsonify({"message": "Usuário bloqueado com sucesso!"}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        cur.close()
        con.close()

@app.route('/desbloquear_usuario/<int:id_usuario>', methods=['PUT'])
def desbloquear_usuario(id_usuario):
    token_data = decodificar_token()
    if not token_data:
        return jsonify({'error': 'Token necessário'}), 401
    if token_data['tipo'] != 0:
        return jsonify({'error': 'Apenas administradores podem desbloquear usuários'}), 403

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
