from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
from openpyxl import load_workbook
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Chave secreta mais segura
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}
app.config['PERMANENT_SESSION_LIFETIME'] = 1800  # 30 minutos

db = SQLAlchemy(app)

@app.template_filter('format_cpf')
def format_cpf(cpf):
    if not cpf:
        return '--'
    cpf = str(cpf).strip().replace('.', '').replace('-', '')
    if len(cpf) == 11:
        return f"{cpf[:3]}.{cpf[3:6]}.{cpf[6:9]}-{cpf[9:]}"
    return cpf

def validar_cpf(cpf):
    cpf = ''.join(filter(str.isdigit, cpf))
    
    if len(cpf) != 11:
        return False
    
    if cpf == cpf[0] * 11:
        return False
    
    soma = 0
    for i in range(9):
        soma += int(cpf[i]) * (10 - i)
    resto = 11 - (soma % 11)
    digito1 = resto if resto < 10 else 0
    
    if digito1 != int(cpf[9]):
        return False
    
    soma = 0
    for i in range(10):
        soma += int(cpf[i]) * (11 - i)
    resto = 11 - (soma % 11)
    digito2 = resto if resto < 10 else 0
    
    return digito2 == int(cpf[10])

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    nome_completo = db.Column(db.String(100), nullable=False)
    cpf = db.Column(db.String(14), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    funcao = db.Column(db.String(50), nullable=False)
    role = db.Column(db.String(20), default='user')
    is_active = db.Column(db.Boolean, default=True)
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow)
    
class DeletedEquipment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patrimonio = db.Column(db.String(50))
    modelo = db.Column(db.String(100))
    data_chegada = db.Column(db.DateTime)
    cpf = db.Column(db.String(14))
    matricula = db.Column(db.String(20))
    carregador = db.Column(db.Boolean, default=False)
    mochila = db.Column(db.Boolean, default=False)
    mouse = db.Column(db.Boolean, default=False)
    termo_path = db.Column(db.String(200))
    data_exclusao = db.Column(db.DateTime, default=datetime.utcnow)
    excluido_por = db.Column(db.Integer, db.ForeignKey('user.id'))
    motivo = db.Column(db.String(200))
    
    usuario = db.relationship('User', backref='exclusoes')
    
class CentroCusto(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    codigo = db.Column(db.String(20), unique=True, nullable=False)
    descricao = db.Column(db.String(100), nullable=False)

class Solicitacao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_solicitacao = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    solicitante_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    destinatario = db.Column(db.String(100), nullable=False)
    centro_custo_id = db.Column(db.Integer, db.ForeignKey('centro_custo.id'), nullable=False)
    observacoes = db.Column(db.Text)
    status = db.Column(db.String(20), default='Pendente')
    aprovador_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    data_aprovacao = db.Column(db.DateTime) 
    
    solicitante = db.relationship('User', foreign_keys=[solicitante_id], backref='solicitacoes')
    aprovador = db.relationship('User', foreign_keys=[aprovador_id])
    centro_custo = db.relationship('CentroCusto', backref='solicitacoes')
    
class Colaborador(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nome_completo = db.Column(db.String(100), nullable=False)
    cpf = db.Column(db.String(14), unique=True, nullable=False)
    funcao = db.Column(db.String(50), nullable=False)
    centro_custo_id = db.Column(db.Integer, db.ForeignKey('centro_custo.id'))
    matricula = db.Column(db.String(20))
    data_cadastro = db.Column(db.DateTime, default=datetime.utcnow)
    
    centro_custo = db.relationship('CentroCusto', backref='colaboradores')
    
class Manutencao(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    equipamento_id = db.Column(db.Integer, db.ForeignKey('equipamento.id'), nullable=False)
    data_abertura = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    data_fechamento = db.Column(db.DateTime)
    motivo = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='aberta')  # aberta, cancelada, realizada
    pecas_trocadas = db.Column(db.Text)
    valor_servico = db.Column(db.Float)
    observacoes = db.Column(db.Text)
    usuario_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    
    equipamento = db.relationship('Equipamento', backref='manutencoes')
    usuario = db.relationship('User', backref='manutencoes')

class Equipamento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patrimonio = db.Column(db.String(50), unique=True, nullable=False)
    modelo = db.Column(db.String(100), nullable=False)
    data_chegada = db.Column(db.DateTime, nullable=False)
    responsavel_id = db.Column(db.Integer, db.ForeignKey('colaborador.id'))
    solicitacao_id = db.Column(db.Integer, db.ForeignKey('solicitacao.id'))  # Adicione esta linha
    cpf = db.Column(db.String(14))
    matricula = db.Column(db.String(20))
    carregador = db.Column(db.Boolean, default=False)
    mochila = db.Column(db.Boolean, default=False)
    mouse = db.Column(db.Boolean, default=False)
    centro_custo_id = db.Column(db.Integer, db.ForeignKey('centro_custo.id'))
    termo_path = db.Column(db.String(200))
    data_retirada = db.Column(db.DateTime)
    
    responsavel = db.relationship('Colaborador', backref='equipamentos')
    solicitacao = db.relationship('Solicitacao', backref='equipamentos')  # Adicione este relacionamento
    centro_custo = db.relationship('CentroCusto', backref='equipamentos')
    
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        
        if user and check_password_hash(user.password, request.form['password']):
            if not user.is_active:
                flash('Sua conta está desativada. Entre em contato com o administrador.', 'danger')
                return redirect(url_for('login'))
            
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['nome_completo'] = user.nome_completo
            flash('Login bem-sucedido!', 'success')
            return redirect(url_for('dashboard'))
        
        flash('Usuário ou senha incorretos.', 'danger')
    return render_template('login.html')

@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    centros_custo = CentroCusto.query.order_by(CentroCusto.codigo).all()  # Carrega os centros
    
    if request.method == 'POST':
        if request.form['password'] != request.form['confirm_password']:
            flash('As senhas não coincidem!', 'danger')
            return redirect(url_for('cadastro'))
        
        cpf = request.form['cpf'].replace('.', '').replace('-', '')
        if not validar_cpf(cpf):
            flash('CPF inválido', 'danger')
            return redirect(url_for('cadastro'))
        
        if User.query.filter_by(username=request.form['username']).first():
            flash('Nome de usuário já existe', 'danger')
            return redirect(url_for('cadastro'))
        
        if User.query.filter_by(email=request.form['email']).first():
            flash('E-mail já cadastrado', 'danger')
            return redirect(url_for('cadastro'))
        
        if User.query.filter_by(cpf=cpf).first():
            flash('CPF já cadastrado', 'danger')
            return redirect(url_for('cadastro'))

        novo_usuario = User(
            username=request.form['username'],
            password=generate_password_hash(request.form['password']),
            nome_completo=request.form['nome_completo'],
            cpf=cpf,
            email=request.form['email'],
            funcao=request.form['funcao'],
            role='user',
            is_active=True
        )
        
        db.session.add(novo_usuario)
        db.session.commit()
        
        flash('Cadastro realizado com sucesso! Faça login para continuar.', 'success')
        return redirect(url_for('login'))
    
    return render_template('cadastro.html', centros_custo=centros_custo)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Estatísticas
    pendentes = Solicitacao.query.filter_by(status='Pendente').count()
    disponiveis = Equipamento.query.filter_by(data_retirada=None).count()
    em_uso = Equipamento.query.filter(Equipamento.data_retirada.isnot(None)).count()
    
    # Últimos registros
    ultimas_solicitacoes = Solicitacao.query.order_by(
        Solicitacao.data_solicitacao.desc()
    ).limit(5).all()
    
    ultimos_equipamentos = Equipamento.query.options(
        db.joinedload(Equipamento.responsavel)
    ).order_by(
        Equipamento.data_chegada.desc()
    ).limit(5).all()
    
    return render_template(
        'dashboard.html',
        username=session['username'],
        pendentes=pendentes,
        disponiveis=disponiveis,
        em_uso=em_uso,
        ultimas_solicitacoes=ultimas_solicitacoes,
        ultimos_equipamentos=ultimos_equipamentos
    )

@app.route('/admin/usuarios')
def admin_usuarios():
    if 'user_id' not in session or session.get('role') != 'main_admin':
        flash('Acesso negado!', 'danger')
        return redirect(url_for('dashboard'))
    
    usuarios = User.query.order_by(User.username).all()
    return render_template('admin_usuarios.html', usuarios=usuarios)

@app.route('/admin/usuario/<int:id>/promover', methods=['POST'])
def promover_usuario(id):
    if 'user_id' not in session or session.get('role') != 'main_admin':
        flash('Acesso negado!', 'danger')
        return redirect(url_for('dashboard'))
    
    usuario = User.query.get_or_404(id)
    usuario.role = 'admin'
    db.session.commit()
    
    flash(f'Usuário {usuario.username} promovido a administrador!', 'success')
    return redirect(url_for('admin_usuarios'))

@app.route('/admin/usuario/<int:id>/rebaixar', methods=['POST'])
def rebaixar_usuario(id):
    if 'user_id' not in session or session.get('role') != 'main_admin':
        flash('Acesso negado!', 'danger')
        return redirect(url_for('dashboard'))
    
    usuario = User.query.get_or_404(id)
    usuario.role = 'user'
    db.session.commit()
    
    flash(f'Usuário {usuario.username} rebaixado a usuário comum!', 'success')
    return redirect(url_for('admin_usuarios'))

@app.route('/admin/usuario/<int:id>/toggle', methods=['POST'])
def toggle_usuario(id):
    if 'user_id' not in session or session.get('role') != 'main_admin':
        flash('Acesso negado!', 'danger')
        return redirect(url_for('dashboard'))
    
    usuario = User.query.get_or_404(id)
    usuario.is_active = not usuario.is_active
    db.session.commit()
    
    status = 'ativado' if usuario.is_active else 'desativado'
    flash(f'Usuário {usuario.username} {status} com sucesso!', 'success')
    return redirect(url_for('admin_usuarios'))

@app.route('/solicitacao/nova', methods=['GET', 'POST'])
def nova_solicitacao():
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('dashboard'))
    
    centros_custo = CentroCusto.query.order_by(CentroCusto.codigo).all()
    
    if request.method == 'POST':
        nova_solicitacao = Solicitacao(
            solicitante_id=session['user_id'],
            destinatario=request.form['destinatario'],
            centro_custo_id=request.form['centro_custo'],
            observacoes=request.form['observacoes']
        )
        db.session.add(nova_solicitacao)
        db.session.commit()
        flash('Solicitação enviada com sucesso!', 'success')
        return redirect(url_for('lista_solicitacoes'))
    
    return render_template('solicitacao.html', centros_custo=centros_custo, datetime=datetime)

@app.route('/admin/colaboradores/novo', methods=['GET', 'POST'])
def novo_colaborador():
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('dashboard'))

    centros_custo = CentroCusto.query.order_by(CentroCusto.codigo).all()
    
    if request.method == 'POST':
        try:
            cpf = ''.join(filter(str.isdigit, request.form['cpf']))
            
            if not validar_cpf(cpf):
                flash('CPF inválido', 'danger')
                return redirect(url_for('novo_colaborador'))

            novo_colab = Colaborador(
                nome_completo=request.form['nome_completo'],
                cpf=cpf,
                funcao=request.form['funcao'],
                centro_custo_id=request.form['centro_custo_id'],
                matricula=request.form.get('matricula')
            )
            
            db.session.add(novo_colab)
            db.session.commit()
            flash('Colaborador cadastrado com sucesso!', 'success')
            return redirect(url_for('lista_colaboradores'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar: {str(e)}', 'danger')

    return render_template('novo_colaborador.html', centros_custo=centros_custo)

@app.route('/admin/colaboradores')
def lista_colaboradores():
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('dashboard'))
    
    colaboradores = Colaborador.query.options(
        db.joinedload(Colaborador.centro_custo)
    ).order_by(Colaborador.nome_completo).all()
    
    return render_template('lista_colaboradores.html', colaboradores=colaboradores)

@app.route('/solicitacoes')
def lista_solicitacoes():
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('dashboard'))
    
    solicitacoes = Solicitacao.query.all()
    return render_template('lista_solicitacoes.html', solicitacoes=solicitacoes)

@app.route('/solicitacao/<int:id>/status', methods=['POST'])
def alterar_status_solicitacao(id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso negado!', 'danger')
        return redirect(url_for('lista_solicitacoes'))
    
    solicitacao = Solicitacao.query.get_or_404(id)
    novo_status = request.form['status']
    solicitacao.status = novo_status
    
    # Registrar quem aprovou/rejeitou
    if novo_status in ['Aprovada', 'Rejeitada']:
        solicitacao.aprovador_id = session['user_id']
        solicitacao.data_aprovacao = datetime.utcnow()
    
    db.session.commit()
    
    flash(f'Solicitação {novo_status.lower()} com sucesso!', 'success')
    return redirect(url_for('lista_solicitacoes'))

@app.route('/equipamento/<int:id>/manutencao', methods=['GET', 'POST'])
def registrar_manutencao(id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('lista_equipamento'))
    
    equipamento = Equipamento.query.get_or_404(id)
    
    if request.method == 'POST':
        try:
            nova_manutencao = Manutencao(
                equipamento_id=id,
                motivo=request.form['motivo'],
                status='aberta',
                pecas_trocadas=request.form.get('pecas_trocadas'),
                valor_servico=float(request.form.get('valor_servico', 0)),
                observacoes=request.form.get('observacoes'),
                usuario_id=session['user_id']
            )
            db.session.add(nova_manutencao)
            db.session.commit()
            flash('Manutenção registrada com sucesso!', 'success')
            return redirect(url_for('lista_manutencoes'))
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao registrar manutenção: {str(e)}', 'danger')
    
    return render_template('registrar_manutencao.html', equipamento=equipamento)

@app.route('/manutencoes')
def lista_manutencoes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    status = request.args.get('status', 'aberta')
    query = Manutencao.query.options(
        db.joinedload(Manutencao.equipamento),
        db.joinedload(Manutencao.usuario)
    ).order_by(Manutencao.data_abertura.desc())
    
    if status in ['aberta', 'cancelada', 'realizada']:
        query = query.filter(Manutencao.status == status)
    
    manutencoes = query.all()
    return render_template('lista_manutencoes.html', manutencoes=manutencoes, status=status)

@app.route('/manutencao/<int:id>/atualizar', methods=['POST'])
def atualizar_manutencao(id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('lista_manutencoes'))
    
    manutencao = Manutencao.query.get_or_404(id)
    novo_status = request.form['status']
    
    try:
        if novo_status == 'realizada':
            manutencao.data_fechamento = datetime.utcnow()
            manutencao.pecas_trocadas = request.form.get('pecas_trocadas', manutencao.pecas_trocadas)
            manutencao.valor_servico = float(request.form.get('valor_servico', manutencao.valor_servico or 0))
        
        manutencao.status = novo_status
        manutencao.observacoes = request.form.get('observacoes', manutencao.observacoes)
        db.session.commit()
        flash('Status da manutenção atualizado com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao atualizar manutenção: {str(e)}', 'danger')
    
    return redirect(url_for('lista_manutencoes', status=request.args.get('status', 'aberta')))

@app.route('/equipamentos/manutencao')
def equipamentos_em_manutencao():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    equipamentos = db.session.query(
        Equipamento,
        CentroCusto.codigo.label('centro_custo_codigo'),
        CentroCusto.descricao.label('centro_custo_descricao')
    ).outerjoin(
        CentroCusto, Equipamento.centro_custo_id == CentroCusto.id
    ).join(
        Manutencao, Manutencao.equipamento_id == Equipamento.id
    ).filter(
        Manutencao.status == 'aberta'
    ).order_by(Manutencao.data_abertura.desc()).all()
    
    return render_template(
        'equipamentos_manutencao.html',
        equipamentos=equipamentos,
        is_admin=session.get('role') in ['admin', 'main_admin']
    )

@app.route('/centro-custo/novo', methods=['GET', 'POST'])
def cadastrar_centro_custo():
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        codigo = request.form['codigo'].strip()
        descricao = request.form['descricao'].strip()
        
        # Verifica se o código já existe
        if CentroCusto.query.filter_by(codigo=codigo).first():
            flash('Já existe um centro de custo com este código!', 'danger')
            return redirect(url_for('cadastrar_centro_custo'))
        
        try:
            novo_centro = CentroCusto(
                codigo=codigo,
                descricao=descricao
            )
            db.session.add(novo_centro)
            db.session.commit()
            flash('Centro de custo cadastrado com sucesso!', 'success')
            return redirect(url_for('lista_colaboradores'))  # Ou para onde faz sentido redirecionar
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar centro de custo: {str(e)}', 'danger')
    
    return render_template('cadastro_centro_custo.html')

@app.route('/equipamento/novo', methods=['GET', 'POST'])
def cadastrar_equipamento():
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('dashboard'))

    # Carrega todos os colaboradores com seus centros de custo
    colaboradores = Colaborador.query.options(
        db.joinedload(Colaborador.centro_custo)
    ).order_by(Colaborador.nome_completo).all()

    if request.method == 'POST':
        try:
            # Verifica se o patrimônio já existe
            patrimonio = request.form['patrimonio']
            if Equipamento.query.filter_by(patrimonio=patrimonio).first():
                flash('Número de patrimônio já cadastrado!', 'danger')
                return redirect(url_for('cadastrar_equipamento'))

            # Cria o novo equipamento
            novo_equipamento = Equipamento(
                patrimonio=patrimonio,
                modelo=request.form['modelo'],
                data_chegada=datetime.strptime(request.form['data_chegada'], '%Y-%m-%dT%H:%M'),
                responsavel_id=request.form['colaborador_id'],
                cpf=request.form['cpf'],
                matricula=request.form.get('matricula'),
                carregador='carregador' in request.form,
                mochila='mochila' in request.form,
                mouse='mouse' in request.form,
                centro_custo_id=request.form['centro_custo_id']
            )

            db.session.add(novo_equipamento)
            db.session.commit()
            flash('Equipamento cadastrado com sucesso!', 'success')
            return redirect(url_for('lista_equipamento'))

        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao cadastrar equipamento: {str(e)}', 'danger')

    return render_template('cadastro_equipamento.html', colaboradores=colaboradores)

@app.route('/equipamento/novo', methods=['POST'])
def cadastrar_equipamento_post():
    try:
        colaborador = Colaborador.query.get(request.form['colaborador_id'])
        
        novo_equipamento = Equipamento(
            patrimonio=request.form['patrimonio'],
            modelo=request.form['modelo'],
            data_chegada=datetime.strptime(request.form['data_chegada'], '%Y-%m-%dT%H:%M'),
            responsavel_id=colaborador.id,
            cpf=colaborador.cpf,
            matricula=request.form.get('matricula'),
            carregador='carregador' in request.form,
            mochila='mochila' in request.form,
            mouse='mouse' in request.form,
            centro_custo_id=colaborador.centro_custo_id  # Usa o centro_custo do colaborador
        )
        
        db.session.add(novo_equipamento)
        db.session.commit()
        flash('Equipamento cadastrado com sucesso!', 'success')
        
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao cadastrar: {str(e)}', 'danger')
    
    return redirect(url_for('lista_equipamento'))

@app.route('/equipamento/<int:id>/excluir', methods=['POST'])
def excluir_equipamento(id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso negado!', 'danger')
        return redirect(url_for('lista_equipamento'))

    equipamento = Equipamento.query.get_or_404(id)
    
    try:
        # Criar registro na tabela de equipamentos excluídos
        deleted_equip = DeletedEquipment(
            patrimonio=equipamento.patrimonio,
            modelo=equipamento.modelo,
            data_chegada=equipamento.data_chegada,
            cpf=equipamento.cpf,
            matricula=equipamento.matricula,
            carregador=equipamento.carregador,
            mochila=equipamento.mochila,
            mouse=equipamento.mouse,
            termo_path=equipamento.termo_path,
            excluido_por=session['user_id'],
            motivo=request.form.get('motivo', 'Sem motivo informado')
        )
        
        db.session.add(deleted_equip)
        db.session.delete(equipamento)
        db.session.commit()
        
        flash('Equipamento excluído com sucesso!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Erro ao excluir equipamento: {str(e)}', 'danger')
    
    return redirect(url_for('lista_equipamento'))

@app.route('/equipamentos/excluidos')
def lista_equipamentos_excluidos():
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso negado!', 'danger')
        return redirect(url_for('dashboard'))

    excluidos = DeletedEquipment.query.options(
        db.joinedload(DeletedEquipment.usuario)
    ).order_by(DeletedEquipment.data_exclusao.desc()).all()
    
    return render_template('lista_excluidos.html', excluidos=excluidos)

@app.route('/equipamentos')
def lista_equipamento():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    centros_custo = CentroCusto.query.order_by(CentroCusto.codigo).all()
    centro_custo_id = request.args.get('centro_custo_id')
    
    query = db.session.query(
        Equipamento,
        CentroCusto.codigo.label('centro_custo_codigo'),
        CentroCusto.descricao.label('centro_custo_descricao')
    ).outerjoin(
        CentroCusto, Equipamento.centro_custo_id == CentroCusto.id  # Corrigido para usar o relacionamento direto
    )
    
    if centro_custo_id:
        query = query.filter(Equipamento.centro_custo_id == centro_custo_id)
    
    resultados = query.order_by(Equipamento.data_chegada.desc()).all()
    
    return render_template(
        'lista_equipamento.html',
        resultados=resultados,
        centros_custo=centros_custo,
        is_admin=session.get('role') in ['admin', 'main_admin']
    )
    
@app.route('/visualizar-equipamento/<int:id>')
def visualizar_equipamento(id):
    if 'user_id' not in session:
        flash('Acesso não autorizado', 'danger')
        return redirect(url_for('login'))

    try:
        equipamento = db.session.query(
            Equipamento,
            Colaborador.nome_completo.label('colaborador_nome'),
            Colaborador.funcao.label('colaborador_funcao'),
            Colaborador.cpf.label('colaborador_cpf'),
            Colaborador.matricula.label('colaborador_matricula'),
            CentroCusto.codigo.label('centro_custo_codigo'),
            CentroCusto.descricao.label('centro_custo_descricao')
        ).outerjoin(
            Colaborador, Equipamento.responsavel_id == Colaborador.id
        ).outerjoin(
            CentroCusto, Equipamento.centro_custo_id == CentroCusto.id
        ).filter(
            Equipamento.id == id
        ).first()

        if not equipamento:
            flash('Equipamento não encontrado', 'danger')
            return redirect(url_for('lista_equipamento'))

        return render_template('visualizar_equipamento.html', equipamento=equipamento[0])

    except Exception as e:
        app.logger.error(f"Erro ao visualizar equipamento: {str(e)}")
        flash('Ocorreu um erro ao carregar o equipamento', 'danger')
        return redirect(url_for('lista_equipamento'))

@app.route('/equipamento/<int:id>/retirada', methods=['POST'])
def registrar_retirada(id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso negado!', 'danger')
        return redirect(url_for('lista_equipamento'))
    
    equipamento = Equipamento.query.get_or_404(id)
    equipamento.data_retirada = datetime.utcnow()
    db.session.commit()
    flash('Retirada do equipamento registrada com sucesso!', 'success')
    return redirect(url_for('visualizar_equipamento', id=id))

@app.route('/equipamento/<int:id>/devolucao', methods=['POST'])
def registrar_devolucao(id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso negado!', 'danger')
        return redirect(url_for('lista_equipamento'))
    
    equipamento = Equipamento.query.get_or_404(id)
    equipamento.data_retirada = None
    db.session.commit()
    flash('Devolução registrada com sucesso!', 'success')
    return redirect(url_for('visualizar_equipamento', id=id))

@app.route('/equipamento/editar/<int:id>', methods=['GET', 'POST'])
def editar_equipamento(id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('lista_equipamento'))

    equipamento = Equipamento.query.get_or_404(id)
    colaboradores = Colaborador.query.order_by(Colaborador.nome_completo).all()
    centros_custo = CentroCusto.query.order_by(CentroCusto.codigo).all()

    if request.method == 'POST':
        try:
            equipamento.patrimonio = request.form['patrimonio']
            equipamento.modelo = request.form['modelo']
            equipamento.data_chegada = datetime.strptime(request.form['data_chegada'], '%Y-%m-%dT%H:%M')
            equipamento.responsavel_id = request.form.get('colaborador_id') or None
            equipamento.cpf = request.form.get('cpf', '').replace('.', '').replace('-', '') if request.form.get('cpf') else None
            equipamento.matricula = request.form.get('matricula')
            equipamento.carregador = 'carregador' in request.form
            equipamento.mochila = 'mochila' in request.form
            equipamento.mouse = 'mouse' in request.form
            equipamento.centro_custo_id = request.form.get('centro_custo_id') or None
            
            db.session.commit()
            flash('Equipamento atualizado com sucesso!', 'success')
            return redirect(url_for('visualizar_equipamento', id=equipamento.id))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Erro ao atualizar equipamento: {str(e)}', 'danger')

    return render_template('editar_equipamento.html', 
                         equipamento=equipamento,
                         colaboradores=colaboradores,
                         centros_custo=centros_custo)
    
@app.route('/equipamento/<int:id>/termo/imprimir')
def imprimir_termo(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    equipamento = Equipamento.query.get_or_404(id)
    if not equipamento.termo_path:
        flash('Nenhum termo disponível para impressão', 'warning')
        return redirect(url_for('visualizar_equipamento', id=id))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], equipamento.termo_path, as_attachment=False)

def criar_banco_de_dados():
    with app.app_context():
        db.drop_all()
        db.create_all()
        
        main_admin = User(
            username='admin_principal',
            password=generate_password_hash('senha_segura_123'),
            nome_completo='Administrador Principal',
            cpf='00000000000',
            email='admin@reframax.com',
            funcao='Administrador',
            role='main_admin',
            is_active=True
        )
        db.session.add(main_admin)
        
        centros_padrao = [
            {'codigo': '2069', 'descricao': 'Alto Forno'},
            {'codigo': '2071', 'descricao': 'Coqueria'},
            {'codigo': '2012', 'descricao': 'Cabeceiras'},
            {'codigo': '2075', 'descricao': 'Aciaria'},
            {'codigo': '2011', 'descricao': 'Vedação'}
        ]
        
        for centro in centros_padrao:
            db.session.add(CentroCusto(**centro))
        
        db.session.commit()
        print("✅ Banco de dados inicializado com sucesso!")

if __name__ == '__main__':
    if not os.path.exists('instance/database.db'):
        criar_banco_de_dados()
    
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True)