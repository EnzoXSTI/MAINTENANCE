from db import conexao
import jwt
import datetime
from flask import request, current_app


# ============================================================
# VERIFICAR SE EMAIL JÁ EXISTE
# ============================================================
def verificar_existente(email, id_usuario=None):
    con = conexao()
    cur = con.cursor()
    try:
        if id_usuario:
            cur.execute("""SELECT 1 FROM USUARIOS
                           WHERE EMAIL = ? AND ID_USUARIO != ?""", (email, id_usuario))
        else:
            cur.execute("""SELECT 1 FROM USUARIOS
                           WHERE EMAIL = ?""", (email,))
        if not cur.fetchone():
            return True
        return False
    except:
        return False
    finally:
        cur.close()
        con.close()


# ============================================================
# VERIFICAR SE SENHAS CORRESPONDEM
# ============================================================
def senha_correspondente(senha, confirmar_senha):
    try:
        return senha == confirmar_senha
    except:
        return False


# ============================================================
# VERIFICAR SE SENHA É FORTE
# ============================================================
def senha_forte(senha):
    try:
        if len(senha) < 8:
            return False
        tem_maiuscula = any(c.isupper() for c in senha)
        tem_minuscula = any(c.islower() for c in senha)
        tem_numero = any(c.isdigit() for c in senha)
        tem_especial = any(not c.isalnum() for c in senha)
        return tem_maiuscula and tem_minuscula and tem_numero and tem_especial
    except:
        return False


# ============================================================
# VERIFICAR SE USUÁRIO EXISTE
# ============================================================
def usuario_existe(id_usuario):
    con = conexao()
    cur = con.cursor()
    try:
        cur.execute("SELECT ID_USUARIO FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario,))
        return cur.fetchone() is not None
    except:
        return False
    finally:
        cur.close()
        con.close()


# ============================================================
# GERAR TOKEN JWT (expira em X minutos)
# ============================================================
def gerar_token(tipo, id_usuario, minutos=10):
    payload = {
        'id_usuario': id_usuario,
        'tipo': tipo,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=minutos)
    }
    token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
    return token


# ============================================================
# DECODIFICAR TOKEN JWT
# ============================================================
def decodificar_token():
    token = request.headers.get('Authorization')
    if not token:
        return False
    try:
        # Suporta "Bearer <token>" ou só o token
        if token.startswith('Bearer '):
            token = token[7:]
        dados = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return dados
    except jwt.ExpiredSignatureError:
        return 'expirado'
    except:
        return False


# ============================================================
# VERIFICAR SE SENHA JÁ FOI USADA (últimas 3)
# ============================================================
def senha_ja_usada(id_usuario, nova_senha):
    from flask_bcrypt import check_password_hash
    con = conexao()
    cur = con.cursor()
    try:
        cur.execute("""SELECT SENHA FROM HISTORICO_SENHAS
                       WHERE ID_USUARIO = ?
                       ORDER BY DATA_ALTERACAO DESC
                       ROWS 3""", (id_usuario,))
        historico = cur.fetchall()
        for row in historico:
            if check_password_hash(row[0], nova_senha):
                return True
        return False
    except:
        return False
    finally:
        cur.close()
        con.close()


# ============================================================
# SALVAR SENHA NO HISTÓRICO
# ============================================================
def salvar_historico_senha(id_usuario, senha_hash, cur):
    data_atual = datetime.datetime.now()
    cur.execute("""INSERT INTO HISTORICO_SENHAS (ID_USUARIO, SENHA, DATA_ALTERACAO)
                   VALUES (?, ?, ?)""", (id_usuario, senha_hash, data_atual))
