import fdb

class USUARIOS:
    def __init__(self, id_usuario, nome, email, senha, tipo, data_cadastro, ativo, email_confirmacao):
        self.id_usuario = id_usuario
        self.nome = nome
        self.email = email
        self.senha = senha
        self.tipo = tipo
        self.data_cadastro = data_cadastro
        self.ativo = ativo
        self.email_confirmacao = email_confirmacao