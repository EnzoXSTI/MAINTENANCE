from db import conexao

# Função para verificar se email já existe
def verificar_existente(email, id_usuario = None):
    # Por padrão, o id_usuario é none (quando não passamos na hora de chamar a função)

    # Cria conexão com o banco
    con = conexao()
    cur = con.cursor()
    try:

        # Se estiver editando um usuário (ignora o próprio id)
        if id_usuario:
            cur.execute("""SELECT 1
                           FROM USUARIOS
                           WHERE EMAIL = ? AND ID_USUARIO != ?""", (email, id_usuario))
        else:
            # Verifica se já existe
            cur.execute("""SELECT 1
                       FROM USUARIOS
                       WHERE EMAIL = ?""", (email,))

        # Se não encontrou, pode usar
        if not cur.fetchone():
            return True
        return False

    except Exception as e:
        return False
    finally:
        cur.close()
        con.close()


# Verifica se as senhas são iguais
def senha_correspondente(senha, confirmar_senha):
    try:
        if senha == confirmar_senha:
            return True
        return False
    except Exception as e:
        return False


# Verifica se a senha é forte
def senha_forte(senha):
    try:
        # Verifica tamanho mínimo
        if len(senha) < 8:
            return False

        # Critérios da senha
        criterios = {
            "maiuscula": False,
            "minuscula": False,
            "numero": False,
            "especial": False
        }

        # Percorre cada caractere
        for s in senha:
            if s.isupper():
                criterios["maiuscula"] = True
            elif s.islower():
                criterios["minuscula"] = True
            elif s.isdigit():
                criterios["numero"] = True
            elif s.isalnum() is False:
                criterios["especial"] = True

        # Verifica se todos os critérios foram atendidos
        if criterios["maiuscula"] == True and criterios["minuscula"] == True and criterios["numero"] == True and criterios["especial"] == True:
            return True

        return False

    except Exception as e:
        return False


# Verifica se o usuário existe
def usuario_existe(id_usuario):
    # Cria conexão com o banco
    con = conexao()
    cur = con.cursor()
    try:
        cur.execute("""SELECT ID_USUARIO
                       FROM USUARIOS
                       WHERE ID_USUARIO = ?""", (id_usuario,))

        # Se encontrou, retorna True
        if cur.fetchone():
            return True
        return False

    except Exception as e:
        return False
    finally:
        cur.close()
        con.close()