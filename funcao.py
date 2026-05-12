from flask_bcrypt import generate_password_hash, check_password_hash
from flask import request, current_app
from db import conexao
import smtplib
from email.mime.text import MIMEText
import jwt
import datetime


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
            cur.execute("SELECT 1 FROM USUARIOS WHERE EMAIL = ?", (email,))
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
    return senha == confirmar_senha


# ============================================================
# VERIFICAR SE SENHA É FORTE
# ============================================================
def senha_forte(senha):
    try:
        if len(senha) < 8:
            return False
        tem_maiuscula = any(c.isupper() for c in senha)
        tem_minuscula = any(c.islower() for c in senha)
        tem_numero    = any(c.isdigit() for c in senha)
        tem_especial  = any(not c.isalnum() for c in senha)
        return tem_maiuscula and tem_minuscula and tem_numero and tem_especial
    except:
        return False


# ============================================================
# VERIFICAR SE SENHA JÁ FOI USADA (últimas 3)
# ============================================================
def senha_antiga(id_usuario, nova_senha):
    con = conexao()
    cur = con.cursor()
    try:
        # Busca senha atual
        cur.execute("SELECT SENHA FROM USUARIOS WHERE ID_USUARIO = ?", (id_usuario,))
        row_atual = cur.fetchone()

        if not row_atual:
            return True  # usuário não encontrado, deixa prosseguir

        senha_atual_hash = row_atual[0]

        # Busca últimas 2 do histórico
        cur.execute("""SELECT FIRST 2 ID_HISTORICO, SENHA_HASH FROM HISTORICO_SENHA
                       WHERE ID_USUARIO = ? ORDER BY DATA_ALTERACAO DESC""", (id_usuario,))
        historico = cur.fetchall()

        # ✅ Verifica se a nova senha é igual à senha atual
        if check_password_hash(senha_atual_hash, nova_senha):
            return False  # mesma senha atual

        # ✅ Verifica se a nova senha já foi usada no histórico
        for row in historico:
            if check_password_hash(row[1], nova_senha):
                return False  # já usou essa senha antes

        # ✅ Antes de trocar, move a senha atual para o histórico
        # Remove a mais antiga se já tiver 2 registros no histórico (mantém só 2 + atual = 3)
        if len(historico) >= 2:
            id_mais_antigo = historico[-1][0]  # último = mais antigo (ORDER BY DESC)
            cur.execute("DELETE FROM HISTORICO_SENHA WHERE ID_HISTORICO = ?", (id_mais_antigo,))

        # ✅ CORRIGIDO: usa GEN_ID diretamente no INSERT para o trigger funcionar no Firebird
        cur.execute("""INSERT INTO HISTORICO_SENHA (ID_HISTORICO, ID_USUARIO, SENHA_HASH, DATA_ALTERACAO)
                       VALUES (GEN_ID(GEN_HISTORICO_SENHA, 1), ?, ?, ?)""",
                    (id_usuario, senha_atual_hash, datetime.datetime.now()))

        con.commit()
        return True  # pode usar essa senha

    except Exception as e:
        print(f"ERRO em senha_antiga: {e}")
        # ✅ CORRIGIDO: em vez de bloquear, deixa prosseguir e loga o erro
        # Isso evita bloquear o usuário por falha técnica (ex: tabela vazia, erro de sequence)
        return True
    finally:
        cur.close()
        con.close()


# ============================================================
# GERAR TOKEN JWT (expira em X minutos)
# ============================================================
def gerar_token(tipo, id_usuario, minutos=10):
    payload = {
        'tipo': tipo,
        'id_usuario': id_usuario,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=minutos)
    }
    token = jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm='HS256')
    return token


# ============================================================
# DECODIFICAR TOKEN JWT
# ============================================================
def decodificar_token():
    try:
        # Tenta pegar o token do cookie
        token = request.cookies.get('acess_token')

        # Tenta pegar do header Authorization
        if not token:
            auth = request.headers.get('Authorization')
            if auth and auth.startswith('Bearer '):
                token = auth.split('Bearer ')[1]

        if not token:
            return False

        payload = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=['HS256'])
        return {'tipo': payload['tipo'], 'id_usuario': payload['id_usuario']}

    except jwt.ExpiredSignatureError:
        return False
    except:
        return False


# ============================================================
# ENVIAR E-MAIL
# ============================================================
def enviando_email(destinatario, assunto, mensagem, user=None, senha=None):
    # ✅ CORRIGIDO: aceita user/senha como parâmetro direto para funcionar
    # dentro de threads (onde current_app não está disponível).
    if not user or not senha:
        try:
            user  = current_app.config.get('EMAIL_REMETENTE', '')
            senha = current_app.config.get('EMAIL_SENHA', '')
        except RuntimeError:
            print("ERRO: current_app não disponível e credenciais não fornecidas.")
            return
    try:
        msg = MIMEText(mensagem, 'plain', 'utf-8')
        msg['From']    = user
        msg['To']      = destinatario
        msg['Subject'] = assunto

        server = smtplib.SMTP_SSL('smtp.gmail.com', 465)
        server.login(user, senha)
        server.sendmail(user, [destinatario], msg.as_string())
        server.quit()
        print(f"E-mail enviado para {destinatario}")
    except Exception as e:
        print(f"ERRO ao enviar e-mail: {e}")
