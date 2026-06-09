from flask import jsonify, request
from main import app
from db import conexao
from funcao import decodificar_token
import os
import datetime


@app.route('/criar_chamado', methods=['POST'])
def criar_chamado():
    token_data = decodificar_token()
    if not token_data:
        return jsonify({'error': 'Token necessário'}), 401

    id_usuario = token_data['id_usuario']
    sala       = request.form.get('sala', None)
    patrimonio = request.form.get('patrimonio', None)
    titulo     = request.form.get('titulo', None)
    descricao  = request.form.get('descricao', None)
    situacao   = request.form.get('situacao', None)
    foto       = request.files.get('foto')

    con = conexao()
    cur = con.cursor()

    try:


        cur.execute("""
            INSERT INTO CHAMADOS (ID_USUARIO, SALA, PATRIMONIO, TITULO, DESCRICAO, SITUACAO, DATA_ABERTURA)
            VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING ID_CHAMADO
        """, (id_usuario, sala.strip(), patrimonio or None, titulo.strip(),
              descricao.strip(), situacao, datetime.datetime.now()))

        id_chamado = cur.fetchone()[0]
        con.commit()

        if foto:
            try:
                pasta = os.path.join(app.config['UPLOAD_FOLDER'], 'Chamados')
                os.makedirs(pasta, exist_ok=True)
                foto.save(os.path.join(pasta, f'{id_chamado}.jpeg'))
            except Exception as e:
                print(f'Erro ao salvar foto: {e}')

        return jsonify({'message': 'Chamado cadastrado com sucesso!', 'id_chamado': id_chamado}), 201

    except Exception as e:
        con.rollback()
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/listar_chamados', methods=['GET'])
def listar_chamados():
    token_data = decodificar_token()
    if not token_data:
        return jsonify({'error': 'Token necessário'}), 401

    con = conexao()
    cur = con.cursor()

    try:
        if token_data['tipo'] in (0, 2):
            cur.execute("""
                SELECT C.ID_CHAMADO, U.NOME, C.SALA, C.TITULO, C.PATRIMONIO,
                       C.SITUACAO, C.DESCRICAO, C.DATA_ABERTURA, C.DATA_FINALIZACAO
                FROM CHAMADOS C
                JOIN USUARIOS U ON U.ID_USUARIO = C.ID_USUARIO
                ORDER BY C.ID_CHAMADO DESC
            """)
        else:
            cur.execute("""
                SELECT C.ID_CHAMADO, U.NOME, C.SALA, C.TITULO, C.PATRIMONIO,
                       C.SITUACAO, C.DESCRICAO, C.DATA_ABERTURA, C.DATA_FINALIZACAO
                FROM CHAMADOS C
                JOIN USUARIOS U ON U.ID_USUARIO = C.ID_USUARIO
                WHERE C.ID_USUARIO = ?
                ORDER BY C.ID_CHAMADO DESC
            """, (token_data['id_usuario'],))

        chamados = []
        for r in cur.fetchall():
            foto_path = os.path.join(app.config['UPLOAD_FOLDER'], 'Chamados', f'{r[0]}.jpeg')
            chamados.append({
                'id_chamado':    r[0],
                'autor':         r[1],
                'sala':          r[2],
                'titulo':        r[3],
                'patrimonio':    r[4],
                'situacao':      r[5],
                'descricao':     r[6],
                'data_abertura':    r[7].strftime('%d/%m/%Y %H:%M') if r[7] else None,
                'data_finalizacao': r[8].strftime('%d/%m/%Y %H:%M') if r[8] else None,
                'foto':             f'/uploads/Chamados/{r[0]}.jpeg' if os.path.exists(foto_path) else None,
            })

        return jsonify({'total': len(chamados), 'chamados': chamados}), 200

    except Exception as e:
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/buscar_chamado/<int:id_chamado>', methods=['GET'])
def buscar_chamado(id_chamado):
    token_data = decodificar_token()
    if not token_data:
        return jsonify({'error': 'Token necessário'}), 401

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT C.ID_CHAMADO, U.NOME, C.SALA, C.TITULO, C.PATRIMONIO,
                   C.SITUACAO, C.DESCRICAO, C.DATA_ABERTURA, C.ID_USUARIO, C.DATA_FINALIZACAO
            FROM CHAMADOS C
            JOIN USUARIOS U ON U.ID_USUARIO = C.ID_USUARIO
            WHERE C.ID_CHAMADO = ?
        """, (id_chamado,))
        r = cur.fetchone()

        if not r:
            return jsonify({'error': 'Chamado não encontrado'}), 404

        if token_data['tipo'] == 1 and r[8] != token_data['id_usuario']:
            return jsonify({'error': 'Acesso negado'}), 403

        cur.execute("""
            SELECT CT.ID_TECNICO, U.NOME
            FROM CHAMADO_TECNICOS CT
            JOIN USUARIOS U ON U.ID_USUARIO = CT.ID_TECNICO
            WHERE CT.ID_CHAMADO = ?
            ORDER BY CT.ID_CHAMADO_TECNICO
        """, (id_chamado,))
        tecnicos = [{'id': t[0], 'nome': t[1]} for t in cur.fetchall()]

        foto_path = os.path.join(app.config['UPLOAD_FOLDER'], 'Chamados', f'{r[0]}.jpeg')

        return jsonify({'chamado': {
            'id_chamado':       r[0],
            'autor':            r[1],
            'sala':             r[2],
            'titulo':           r[3],
            'patrimonio':       r[4],
            'situacao':         r[5],
            'descricao':        r[6],
            'data_abertura':    r[7].strftime('%d/%m/%Y %H:%M') if r[7] else None,
            'data_finalizacao': r[9].strftime('%d/%m/%Y %H:%M') if r[9] else None,
            'tecnicos':         tecnicos,
            'foto':             f'/uploads/Chamados/{r[0]}.jpeg' if os.path.exists(foto_path) else None,
        }}), 200

    except Exception as e:
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/atualizar_chamado/<int:id_chamado>', methods=['PUT'])
def atualizar_chamado(id_chamado):
    token_data = decodificar_token()
    if not token_data:
        return jsonify({'error': 'Token necessário'}), 401

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("SELECT ID_USUARIO FROM CHAMADOS WHERE ID_CHAMADO = ?", (id_chamado,))
        chamado = cur.fetchone()

        if not chamado:
            return jsonify({'error': 'Chamado não encontrado'}), 404

        # Usuário comum só edita o próprio chamado
        if token_data['tipo'] == 1 and chamado[0] != token_data['id_usuario']:
            return jsonify({'error': 'Acesso negado'}), 403

        sala       = request.form.get('sala', None)
        patrimonio = request.form.get('patrimonio', None)
        titulo     = request.form.get('titulo', None)
        descricao  = request.form.get('descricao', None)
        situacao   = request.form.get('situacao', None)



        cur.execute("""
            UPDATE CHAMADOS SET SALA = ?, PATRIMONIO = ?, TITULO = ?, DESCRICAO = ?, SITUACAO = ?
            WHERE ID_CHAMADO = ?
        """, (sala.strip(), patrimonio or None, titulo.strip(), descricao.strip(), situacao, id_chamado))
        con.commit()

        return jsonify({'message': 'Chamado atualizado com sucesso!'}), 200

    except Exception as e:
        con.rollback()
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/concluir_chamado/<int:id_chamado>', methods=['PUT'])
def concluir_chamado(id_chamado):
    token_data = decodificar_token()
    if not token_data:
        return jsonify({'error': 'Token necessário'}), 401

    if token_data['tipo'] == 1:
        return jsonify({'error': 'Sem permissão para concluir chamados'}), 403

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("SELECT SITUACAO FROM CHAMADOS WHERE ID_CHAMADO = ?", (id_chamado,))
        row = cur.fetchone()

        if not row:
            return jsonify({'error': 'Chamado não encontrado'}), 404
        if row[0] == 'Finalizado':
            return jsonify({'error': 'Chamado já está finalizado'}), 400

        cur.execute("""
            UPDATE CHAMADOS SET SITUACAO = 'Finalizado', DATA_FINALIZACAO = ?
            WHERE ID_CHAMADO = ?
        """, (datetime.datetime.now(), id_chamado))
        con.commit()

        return jsonify({'message': 'Chamado concluído com sucesso!'}), 200

    except Exception as e:
        con.rollback()
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/listar_tecnicos', methods=['GET'])
def listar_tecnicos():
    token_data = decodificar_token()
    if not token_data:
        return jsonify({'error': 'Token necessário'}), 401
    if token_data['tipo'] != 0:
        return jsonify({'error': 'Apenas ADM pode listar técnicos'}), 403

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("""
            SELECT ID_USUARIO, NOME FROM USUARIOS
            WHERE TIPO = 2 AND ATIVO = 1
            ORDER BY NOME
        """)
        tecnicos = [{'id': r[0], 'nome': r[1]} for r in cur.fetchall()]

        return jsonify({'total': len(tecnicos), 'tecnicos': tecnicos}), 200

    except Exception as e:
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/atribuir_tecnicos/<int:id_chamado>', methods=['PUT'])
def atribuir_tecnicos(id_chamado):
    token_data = decodificar_token()
    if not token_data:
        return jsonify({'error': 'Token necessário'}), 401

    tipo       = token_data['tipo']
    id_usuario = token_data['id_usuario']

    if tipo == 1:
        return jsonify({'error': 'Sem permissão para atribuir técnicos'}), 403

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("SELECT ID_CHAMADO FROM CHAMADOS WHERE ID_CHAMADO = ?", (id_chamado,))
        if not cur.fetchone():
            return jsonify({'error': 'Chamado não encontrado'}), 404

        cur.execute("SELECT ID_TECNICO FROM CHAMADO_TECNICOS WHERE ID_CHAMADO = ?", (id_chamado,))
        atuais = [row[0] for row in cur.fetchall()]

        # ADM: define a lista completa de técnicos
        if tipo == 0:
            ids_raw = request.form.getlist('tecnicos')
            try:
                ids = [int(i) for i in ids_raw if i]
            except ValueError:
                return jsonify({'error': 'IDs inválidos'}), 400

            ids = list(dict.fromkeys(ids))  # remove duplicatas mantendo a ordem

            for tid in ids:
                cur.execute("SELECT TIPO FROM USUARIOS WHERE ID_USUARIO = ?", (tid,))
                u = cur.fetchone()
                if not u or u[0] != 2:
                    return jsonify({'error': f'Usuário {tid} não é técnico'}), 400

            cur.execute("DELETE FROM CHAMADO_TECNICOS WHERE ID_CHAMADO = ?", (id_chamado,))
            for tid in ids:
                cur.execute("""
                    INSERT INTO CHAMADO_TECNICOS (ID_CHAMADO_TECNICO, ID_CHAMADO, ID_TECNICO)
                    VALUES (GEN_ID(GEN_CHAMADO_TECNICOS, 1), ?, ?)
                """, (id_chamado, tid))
            con.commit()

        # Técnico: se auto-atribui, apenas se não houver nenhum técnico ainda
        elif tipo == 2:
            if id_usuario in atuais:
                return jsonify({'error': 'Você já está atribuído a este chamado'}), 400
            if len(atuais) > 0:
                return jsonify({'error': 'Este chamado já tem um técnico. Somente o ADM pode atribuir mais técnicos'}), 400

            cur.execute("""
                INSERT INTO CHAMADO_TECNICOS (ID_CHAMADO_TECNICO, ID_CHAMADO, ID_TECNICO)
                VALUES (GEN_ID(GEN_CHAMADO_TECNICOS, 1), ?, ?)
            """, (id_chamado, id_usuario))
            con.commit()

        cur.execute("""
            SELECT CT.ID_TECNICO, U.NOME FROM CHAMADO_TECNICOS CT
            JOIN USUARIOS U ON U.ID_USUARIO = CT.ID_TECNICO
            WHERE CT.ID_CHAMADO = ?
            ORDER BY CT.ID_CHAMADO_TECNICO
        """, (id_chamado,))
        tecnicos = [{'id': t[0], 'nome': t[1]} for t in cur.fetchall()]

        return jsonify({'message': 'Técnicos atribuídos com sucesso!', 'tecnicos': tecnicos}), 200

    except Exception as e:
        con.rollback()
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()


@app.route('/deletar_chamado/<int:id_chamado>', methods=['DELETE'])
def deletar_chamado(id_chamado):
    token_data = decodificar_token()
    if not token_data:
        return jsonify({'error': 'Token necessário'}), 401

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("SELECT ID_CHAMADO FROM CHAMADOS WHERE ID_CHAMADO = ?", (id_chamado,))
        if not cur.fetchone():
            return jsonify({'error': 'Chamado não encontrado'}), 404

        # Remove os vínculos dos técnicos primeiro (chave estrangeira) e depois o chamado
        cur.execute("DELETE FROM CHAMADO_TECNICOS WHERE ID_CHAMADO = ?", (id_chamado,))
        cur.execute("DELETE FROM CHAMADOS WHERE ID_CHAMADO = ?", (id_chamado,))
        con.commit()

        # Remove a foto se ela existir
        foto_path = os.path.join(app.config['UPLOAD_FOLDER'], 'Chamados', f'{id_chamado}.jpeg')
        if os.path.exists(foto_path):
            os.remove(foto_path)

        return jsonify({'message': 'Chamado deletado com sucesso!'}), 200

    except Exception as e:
        con.rollback()
        return jsonify({'error': f'Erro: {e}'}), 500
    finally:
        cur.close()
        con.close()
