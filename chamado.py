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

    id_usuario  = token_data['id_usuario']
    sala        = request.form.get('sala', '').strip()
    patrimonio  = request.form.get('patrimonio', '').strip()
    titulo      = request.form.get('titulo', '').strip()
    descricao   = request.form.get('descricao', '').strip()
    situacao    = request.form.get('situacao', '').strip()
    foto        = request.files.get('foto')

    if not sala:
        return jsonify({'error': 'Sala é obrigatória'}), 400
    if not titulo:
        return jsonify({'error': 'Título é obrigatório'}), 400
    if not descricao:
        return jsonify({'error': 'Descrição é obrigatória'}), 400
    if not situacao:
        return jsonify({'error': 'Situação é obrigatória'}), 400

    SITUACOES_VALIDAS = ['Aguardando', 'Em andamento', 'Finalizado']
    if situacao not in SITUACOES_VALIDAS:
        return jsonify({'error': 'Situação inválida'}), 400

    con = conexao()
    cur = con.cursor()

    try:
        data_abertura = datetime.datetime.now()

        cur.execute("""
            INSERT INTO CHAMADOS (ID_USUARIO, SALA, PATRIMONIO, TITULO, DESCRICAO, SITUACAO, DATA_ABERTURA)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            RETURNING ID_CHAMADO
        """, (id_usuario, sala, patrimonio or None, titulo, descricao, situacao, data_abertura))

        id_chamado = cur.fetchone()[0]
        con.commit()

        if foto:
            try:
                pasta = os.path.join(app.config['UPLOAD_FOLDER'], 'Chamados')
                os.makedirs(pasta, exist_ok=True)
                caminho = os.path.join(pasta, f'{id_chamado}.jpeg')
                foto.save(caminho)
            except Exception as e:
                print(f'Erro ao salvar foto do chamado: {e}')

        return jsonify({'message': 'Chamado cadastrado com sucesso!', 'id_chamado': id_chamado}), 201

    except Exception as e:
        con.rollback()
        print(f'Erro ao criar chamado: {e}')
        return jsonify({'error': f'Erro ao cadastrar chamado: {e}'}), 500
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
        # Admin (tipo 0) vê todos; demais só veem os próprios
        if token_data['tipo'] == 0:
            cur.execute("""
                SELECT C.ID_CHAMADO, U.NOME, C.SALA, C.TITULO, C.PATRIMONIO,
                       C.SITUACAO, C.DESCRICAO, C.DATA_ABERTURA
                FROM CHAMADOS C
                JOIN USUARIOS U ON U.ID_USUARIO = C.ID_USUARIO
                ORDER BY C.ID_CHAMADO DESC
            """)
        else:
            cur.execute("""
                SELECT C.ID_CHAMADO, U.NOME, C.SALA, C.TITULO, C.PATRIMONIO,
                       C.SITUACAO, C.DESCRICAO, C.DATA_ABERTURA
                FROM CHAMADOS C
                JOIN USUARIOS U ON U.ID_USUARIO = C.ID_USUARIO
                WHERE C.ID_USUARIO = ?
                ORDER BY C.ID_CHAMADO DESC
            """, (token_data['id_usuario'],))

        rows = cur.fetchall()
        chamados = []
        for r in rows:
            foto_path = os.path.join(app.config['UPLOAD_FOLDER'], 'Chamados', f'{r[0]}.jpeg')
            tem_foto  = os.path.exists(foto_path)
            chamados.append({
                'id_chamado':    r[0],
                'autor':         r[1],
                'sala':          r[2],
                'titulo':        r[3],
                'patrimonio':    r[4],
                'situacao':      r[5],
                'descricao':     r[6],
                'data_abertura': r[7].strftime('%d/%m/%Y %H:%M') if r[7] else None,
                'foto':          f'/uploads/Chamados/{r[0]}.jpeg' if tem_foto else None,
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
                   C.SITUACAO, C.DESCRICAO, C.DATA_ABERTURA, C.ID_USUARIO
            FROM CHAMADOS C
            JOIN USUARIOS U ON U.ID_USUARIO = C.ID_USUARIO
            WHERE C.ID_CHAMADO = ?
        """, (id_chamado,))
        r = cur.fetchone()

        if not r:
            return jsonify({'error': 'Chamado não encontrado'}), 404

        # Usuário comum só pode ver o próprio chamado
        if token_data['tipo'] != 0 and r[8] != token_data['id_usuario']:
            return jsonify({'error': 'Acesso negado'}), 403

        foto_path = os.path.join(app.config['UPLOAD_FOLDER'], 'Chamados', f'{r[0]}.jpeg')
        tem_foto  = os.path.exists(foto_path)

        return jsonify({'chamado': {
            'id_chamado':    r[0],
            'autor':         r[1],
            'sala':          r[2],
            'titulo':        r[3],
            'patrimonio':    r[4],
            'situacao':      r[5],
            'descricao':     r[6],
            'data_abertura': r[7].strftime('%d/%m/%Y %H:%M') if r[7] else None,
            'foto':          f'/uploads/Chamados/{r[0]}.jpeg' if tem_foto else None,
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
        cur.execute("SELECT ID_USUARIO, SITUACAO FROM CHAMADOS WHERE ID_CHAMADO = ?", (id_chamado,))
        chamado = cur.fetchone()

        if not chamado:
            return jsonify({'error': 'Chamado não encontrado'}), 404

        # Somente admin ou dono pode editar
        if token_data['tipo'] != 0 and chamado[0] != token_data['id_usuario']:
            return jsonify({'error': 'Acesso negado'}), 403

        sala       = request.form.get('sala', '').strip()
        patrimonio = request.form.get('patrimonio', '').strip()
        titulo     = request.form.get('titulo', '').strip()
        descricao  = request.form.get('descricao', '').strip()
        situacao   = request.form.get('situacao', '').strip()

        if not sala or not titulo or not descricao or not situacao:
            return jsonify({'error': 'Preencha todos os campos obrigatórios'}), 400

        SITUACOES_VALIDAS = ['Aguardando', 'Em andamento', 'Urgente', 'Finalizado']
        if situacao not in SITUACOES_VALIDAS:
            return jsonify({'error': 'Situação inválida'}), 400

        cur.execute("""
            UPDATE CHAMADOS
            SET SALA = ?, PATRIMONIO = ?, TITULO = ?, DESCRICAO = ?, SITUACAO = ?
            WHERE ID_CHAMADO = ?
        """, (sala, patrimonio or None, titulo, descricao, situacao, id_chamado))
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

    # Apenas admin pode concluir
    if token_data['tipo'] != 0:
        return jsonify({'error': 'Apenas administradores podem concluir chamados'}), 403

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("SELECT ID_CHAMADO FROM CHAMADOS WHERE ID_CHAMADO = ?", (id_chamado,))
        if not cur.fetchone():
            return jsonify({'error': 'Chamado não encontrado'}), 404

        cur.execute("UPDATE CHAMADOS SET SITUACAO = 'Finalizado' WHERE ID_CHAMADO = ?", (id_chamado,))
        con.commit()

        return jsonify({'message': 'Chamado concluído com sucesso!'}), 200

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
    if token_data['tipo'] != 0:
        return jsonify({'error': 'Apenas administradores podem deletar chamados'}), 403

    con = conexao()
    cur = con.cursor()

    try:
        cur.execute("SELECT ID_CHAMADO FROM CHAMADOS WHERE ID_CHAMADO = ?", (id_chamado,))
        if not cur.fetchone():
            return jsonify({'error': 'Chamado não encontrado'}), 404

        cur.execute("DELETE FROM CHAMADOS WHERE ID_CHAMADO = ?", (id_chamado,))
        con.commit()

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
