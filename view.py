from flask import jsonify, request, make_response
from funcao import senha_forte, verificar_existente, senha_correspondente
from flask_bcrypt import generate_password_hash, check_password_hash
from main import app
from db import conexao
import os
import datetime


# Criar usuário
@app.route('/criar_usuarios', methods=['POST'])
def criar_usuarios():
    # Pega as informações do body
    nome = request.form.get('nome', None)
    email = request.form.get('email', None)
    senha = request.form.get('senha')
    confirmar_senha = request.form.get('confirmar_senha')
    foto_perfil = request.files.get('foto_perfil')

    # Tipo 0 - ADM | Tipo 1 - professor | Tipo 2 - tecnico
    tipo = request.form.get('tipo', 1)

    # Converte para inteiro
    try:
        tipo = int(tipo)
    except (ValueError, TypeError):
        tipo = 1

    data_cadastro = datetime.datetime.now()
    ativo = 1
    email_confirmacao = 0

    # Conexão com o banco
    con = conexao()
    cur = con.cursor()

    try:
        # Verifica se o nome está vazio
        if nome == None or nome.strip() == '':
            return jsonify({"error": "Nome é uma informação obrigatória."}), 400

        # Verifica se o email está vazio
        if email == None or email.strip() == '':
            return jsonify({"error": "E-mail é uma informação obrigatória."}), 400

        # Verifica se o e-mail já está cadastrado
        if verificar_existente(email, 2) == False:
            return jsonify({"error": "E-mail já cadastrado"}), 400

        # Verifica se a senha é forte
        if senha_forte(senha) == False:
            return jsonify({
                "error": "Senha fraca. A senha deve conter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."
            }), 400

        # Verifica se as senhas digitadas correspondem
        if senha_correspondente(senha, confirmar_senha) == False:
            return jsonify({"error": "Senhas não correspondem."}), 400

        # Criptografa a senha
        senha_cripto = generate_password_hash(senha).decode('utf-8')

        # Insere o usuário no banco de dados
        cur.execute("""INSERT INTO USUARIOS (NOME, EMAIL, SENHA, TIPO, DATA_CADASTRO, ATIVO, EMAIL_CONFIRMACAO)
                       VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING ID_USUARIO""",
                    (nome, email, senha_cripto, tipo, data_cadastro, ativo, email_confirmacao))

        # Recupera o ID do usuário recém criado
        id_usuario = cur.fetchone()[0]
        con.commit()

        # Verifica se foi enviada uma foto de perfil
        if foto_perfil:
            try:
                # Define o nome da imagem com base no ID do usuário
                nome_imagem = f'{id_usuario}.jpeg'

                # Define a pasta de destino
                caminho_imagem_destino = os.path.join(app.config['UPLOAD_FOLDER'], 'Usuarios')

                # Cria a pasta caso não exista
                os.makedirs(caminho_imagem_destino, exist_ok=True)

                # Define o caminho completo da imagem
                caminho_imagem = os.path.join(caminho_imagem_destino, nome_imagem)

                # Salva a imagem no diretório
                foto_perfil.save(caminho_imagem)
            except Exception as e:
                print(f"ERRO ao salvar imagem: {e}")

        # Retorna sucesso com os dados do usuário
        return jsonify({
            'message': "Usuário cadastrado com sucesso",
            'usuario': {
                'id': id_usuario,
                'nome': nome,
                'email': email,
                'tipo': tipo
            }
        }), 201

    except Exception as e:
        print(f"ERRO ao cadastrar usuário: {e}")
        return jsonify({'message': f'Erro ao consultar o banco de dados: {e}'}), 500
    finally:
        cur.close()
        con.close()


# Editar usuário
@app.route('/editar_usuarios/<int:id_usuario>', methods=['PUT'])
def editar_usuarios(id_usuario):
    # Cria a conexão com o banco
    con = conexao()

    # Abre o cursor
    cur = con.cursor()

    try:
        # Busca os dados atuais do usuário
        cur.execute("""SELECT ID_USUARIO, NOME, EMAIL, SENHA, TIPO
                       FROM USUARIOS
                       WHERE ID_USUARIO = ?""", (id_usuario,))

        # Armazena o resultado
        tem_usuario = cur.fetchone()

        # Verifica se o usuário existe
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
            if verificar_existente(email, 2, id_usuario) == False:
                return jsonify({"error": "E-mail já cadastrado"}), 400

        # Verifica se foi enviada uma nova senha
        if senha != None:
            # Valida a força da senha
            if senha_forte(senha) == False:
                return jsonify({
                    "error": "Senha fraca. A senha deve conter pelo menos 8 caracteres, incluindo letras maiúsculas, minúsculas, números e caracteres especiais."
                }), 400

            # Verifica se as senhas correspondem
            if senha_correspondente(senha, confirmar_senha) == False:
                return jsonify({"error": "Senhas não correspondem."}), 400

            # Criptografa a nova senha
            nova_senha_hash = generate_password_hash(senha).decode('utf-8')
        else:
            # Mantém a senha antiga
            nova_senha_hash = tem_usuario[3]

        # Atualiza os dados do usuário no banco
        cur.execute("""UPDATE USUARIOS
                       SET NOME = ?,
                           EMAIL = ?,
                           SENHA = ?
                       WHERE ID_USUARIO = ?""", (nome, email, nova_senha_hash, id_usuario))

        # Confirma a alteração no banco
        con.commit()

        # Verifica se foi enviada uma nova foto
        if foto_perfil:
            try:
                # Define nome da imagem
                nome_imagem = f'{id_usuario}.jpeg'

                # Define diretório
                caminho_imagem_destino = os.path.join(app.config['UPLOAD_FOLDER'], "Usuarios")

                # Cria diretório se não existir
                os.makedirs(caminho_imagem_destino, exist_ok=True)

                # Define caminho completo
                caminho_imagem = os.path.join(caminho_imagem_destino, nome_imagem)

                # Salva imagem
                foto_perfil.save(caminho_imagem)
            except Exception as e:
                print(f"ERRO ao salvar imagem: {e}")

        # Retorna sucesso
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


# Buscar usuário
@app.route('/buscar_usuarios/<int:id_usuario>', methods=['GET'])
def buscar_usuarios(id_usuario):
    # Cria conexão com o banco
    con = conexao()

    # Abre o cursor
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

        # Verifica se o usuário existe
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


# Listar usuários
@app.route('/listar_usuarios', methods=['GET'])
def listar_usuarios():
    # Cria conexão
    con = conexao()

    # Abre cursor
    cur = con.cursor()

    try:
        # Busca todos os usuários
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


# Excluir usuário
@app.route('/deletar_usuarios/<int:id_usuario>', methods=['DELETE'])
def deletar_usuarios(id_usuario):
    # Cria a conexão com o banco
    con = conexao()

    # Abre o cursor
    cur = con.cursor()

    try:
        # Verifica se o usuário existe
        cur.execute("""SELECT ID_USUARIO, NOME
                       FROM USUARIOS
                       WHERE ID_USUARIO = ?""", (id_usuario,))

        usuario = cur.fetchone()

        if usuario == None:
            return jsonify({"error": "Usuário não encontrado"}), 404

        # Remove foto se existir
        caminho_foto = os.path.join(app.config['UPLOAD_FOLDER'], f'Usuarios/{id_usuario}.jpeg')
        if os.path.exists(caminho_foto):
            os.remove(caminho_foto)

        # Remove o usuário da tabela principal
        cur.execute("""DELETE
                       FROM USUARIOS
                       WHERE ID_USUARIO = ?""", (id_usuario,))

        con.commit()

        # Retorna sucesso
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