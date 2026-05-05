from db import conexao

# Função para verificar se email já existe
def verificar_existente(email, id_usuario = None):

    con = conexao()
    cur = con.cursor()
    try:

        if id_usuario:
            cur.execute("""SELECT 1
                           FROM USUARIOS
                           WHERE EMAIL = ? AND ID_USUARIO != ?""", (email, id_usuario))
        else:
            cur.execute("""SELECT 1
                       FROM USUARIOS
                       WHERE EMAIL = ?""", (email,))

        if not cur.fetchone():
            return True
        return False

    except Exception as e:
        return False
    finally:
        cur.close()
        con.close()


def senha_correspondente(senha, confirmar_senha):
    try:
        if senha == confirmar_senha:
            return True
        return False
    except Exception as e:
        return False


def senha_forte(senha):
    try:
        if len(senha) < 8:
            return False

        criterios = {
            "maiuscula": False,
            "minuscula": False,
            "numero": False,
            "especial": False
        }

        for s in senha:
            if s.isupper():
                criterios["maiuscula"] = True
            elif s.islower():
                criterios["minuscula"] = True
            elif s.isdigit():
                criterios["numero"] = True
            elif s.isalnum() is False:
                criterios["especial"] = True

        if criterios["maiuscula"] == True and criterios["minuscula"] == True and criterios["numero"] == True and criterios["especial"] == True:
            return True

        return False

    except Exception as e:
        return False


def usuario_existe(id_usuario):

    con = conexao()
    cur = con.cursor()
    try:
        cur.execute("""SELECT ID_USUARIO
                       FROM USUARIOS
                       WHERE ID_USUARIO = ?""", (id_usuario,))

        if cur.fetchone():
            return True
        return False

    except Exception as e:
        return False
    finally:
        cur.close()
        con.close()