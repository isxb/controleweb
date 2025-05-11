from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'sua_chave_secreta_aqui_123'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['ALLOWED_EXTENSIONS'] = {'pdf'}

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
    
    solicitante = db.relationship('User', backref='solicitacoes')
    centro_custo = db.relationship('CentroCusto', backref='solicitacoes')

class Equipamento(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    data_chegada = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    patrimonio = db.Column(db.String(50), unique=True, nullable=False)
    responsavel_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    cpf = db.Column(db.String(14))
    matricula = db.Column(db.String(20))
    modelo = db.Column(db.String(100), nullable=False)
    carregador = db.Column(db.Boolean, default=False)
    mochila = db.Column(db.Boolean, default=False)
    mouse = db.Column(db.Boolean, default=False)
    data_retirada = db.Column(db.DateTime)
    termo_path = db.Column(db.String(200))
    solicitacao_id = db.Column(db.Integer, db.ForeignKey('solicitacao.id'))
    data_devolucao = db.Column(db.DateTime)
    motivo_devolucao = db.Column(db.String(50))
    termo_devolucao_path = db.Column(db.String(200))
    data_envio_sede = db.Column(db.DateTime)
    acessorios_devolvidos = db.Column(db.String(200))
    defeito_relatado = db.Column(db.Text)
    desconto_aplicado = db.Column(db.Float, default=0.0)
    em_manutencao = db.Column(db.Boolean, default=False)
    problemas_manutencao = db.Column(db.Text)
    
    responsavel = db.relationship('User', backref='equipamentos')
    solicitacao = db.relationship('Solicitacao', backref='equipamento')

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
    
    return render_template('cadastro.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    pendentes = Solicitacao.query.filter_by(status='Pendente').count()
    aprovadas = Solicitacao.query.filter_by(status='Aprovada').count()
    rejeitadas = Solicitacao.query.filter_by(status='Rejeitada').count()
    em_manutencao = Equipamento.query.filter_by(em_manutencao=True).count()
    
    return render_template(
        'dashboard.html',
        username=session['username'],
        pendentes=pendentes,
        aprovadas=aprovadas,
        rejeitadas=rejeitadas,
        em_manutencao=em_manutencao
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

@app.route('/solicitacoes')
def lista_solicitacoes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
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
    db.session.commit()
    
    flash(f'Solicitação {novo_status.lower()} com sucesso!', 'success')
    return redirect(url_for('lista_solicitacoes'))

@app.route('/centro-custo/novo', methods=['GET', 'POST'])
def cadastrar_centro_custo():
    if 'user_id' not in session or session['role'] != 'admin':
        flash('Acesso negado!', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        novo_centro = CentroCusto(
            codigo=request.form['codigo'],
            descricao=request.form['descricao']
        )
        db.session.add(novo_centro)
        db.session.commit()
        flash('Centro de custo cadastrado!', 'success')
        return redirect(url_for('nova_solicitacao'))
    
    return render_template('cadastro_centro_custo.html')

@app.route('/equipamento/novo', methods=['GET', 'POST'])
def cadastrar_equipamento():
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso restrito a administradores', 'danger')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        termo_path = None
        if 'termo' in request.files:
            file = request.files['termo']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                termo_path = filename
        
        cpf = request.form['cpf'].replace('.', '').replace('-', '') if request.form['cpf'] else None
        
        novo_equipamento = Equipamento(
            patrimonio=request.form['patrimonio'],
            modelo=request.form['modelo'],
            data_chegada=datetime.strptime(request.form['data_chegada'], '%Y-%m-%dT%H:%M'),
            responsavel_id=request.form['responsavel_id'] or None,
            cpf=cpf,
            matricula=request.form['matricula'],
            carregador='carregador' in request.form,
            mochila='mochila' in request.form,
            mouse='mouse' in request.form,
            termo_path=termo_path
        )
        db.session.add(novo_equipamento)
        db.session.commit()
        flash('Equipamento cadastrado com sucesso!', 'success')
        return redirect(url_for('lista_equipamentos'))
    
    usuarios = User.query.all()
    return render_template('cadastro_equipamento.html', usuarios=usuarios)

@app.route('/equipamentos')
def lista_equipamentos():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    query = Equipamento.query.filter(Equipamento.data_devolucao.is_(None))
    
    if 'patrimonio' in request.args and request.args['patrimonio']:
        query = query.filter(Equipamento.patrimonio.contains(request.args['patrimonio']))
    
    if 'responsavel' in request.args and request.args['responsavel']:
        query = query.join(User).filter(User.username.contains(request.args['responsavel']))
    
    if 'cpf' in request.args and request.args['cpf']:
        cpf_search = request.args['cpf'].replace('.', '').replace('-', '')
        query = query.filter(Equipamento.cpf.contains(cpf_search))
    
    equipamentos = query.order_by(Equipamento.data_chegada.desc()).all()
    return render_template('lista_equipamentos.html', equipamentos=equipamentos)

@app.route('/equipamentos/devolvidos')
def lista_equipamentos_devolvidos():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    equipamentos = Equipamento.query.filter(Equipamento.data_devolucao.isnot(None))\
                      .order_by(Equipamento.data_devolucao.desc()).all()
    return render_template('lista_equipamentos_devolvidos.html', equipamentos=equipamentos)

@app.route('/equipamento/<int:id>')
def visualizar_equipamento(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    equipamento = Equipamento.query.get_or_404(id)
    return render_template('visualizar_equipamento.html', equipamento=equipamento)

@app.route('/equipamento/<int:id>/baixa', methods=['GET', 'POST'])
def registrar_baixa(id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso negado!', 'danger')
        return redirect(url_for('lista_equipamentos'))
    
    equipamento = Equipamento.query.get_or_404(id)
    
    if request.method == 'POST':
        equipamento.data_devolucao = datetime.utcnow()
        equipamento.motivo_devolucao = request.form['motivo']
        equipamento.defeito_relatado = request.form.get('defeito', '')
        equipamento.data_retirada = None  # Remove o status de retirado
        
        if 'termo_devolucao' in request.files:
            file = request.files['termo_devolucao']
            if file and allowed_file(file.filename):
                filename = f"devolucao_{equipamento.patrimonio}_{datetime.now().strftime('%Y%m%d')}.pdf"
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                equipamento.termo_devolucao_path = filename
        
        acessorios = []
        if 'carregador_devolvido' in request.form:
            acessorios.append('Carregador')
        if 'mochila_devolvida' in request.form:
            acessorios.append('Mochila')
        if 'mouse_devolvido' in request.form:
            acessorios.append('Mouse')
        equipamento.acessorios_devolvidos = ', '.join(acessorios)
        
        
        db.session.commit()
        flash('Baixa do equipamento registrada com sucesso!', 'success')
        return redirect(url_for('lista_equipamentos_devolvidos'))
    
    return render_template('registrar_baixa.html', equipamento=equipamento)

@app.route('/equipamento/<int:id>/manutencao', methods=['GET', 'POST'])
def registrar_manutencao(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    equipamento = Equipamento.query.get_or_404(id)
    
    if request.method == 'POST':
        equipamento.em_manutencao = True
        equipamento.problemas_manutencao = request.form['problema']
        equipamento.data_retirada = None  # Permite nova retirada após manutenção
        db.session.commit()
        flash('Equipamento enviado para manutenção!', 'success')
        return redirect(url_for('lista_manutencoes'))
    
    return render_template('registrar_manutencao.html', equipamento=equipamento)

@app.route('/manutencoes')
def lista_manutencoes():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    equipamentos = Equipamento.query.filter_by(em_manutencao=True).all()
    return render_template('lista_manutencoes.html', equipamentos=equipamentos)

@app.route('/equipamento/<int:id>/concluir-manutencao', methods=['POST'])
def concluir_manutencao(id):
    if 'user_id' not in session or session.get('role') not in ['admin', 'main_admin']:
        flash('Acesso negado!', 'danger')
        return redirect(url_for('lista_manutencoes'))
    
    equipamento = Equipamento.query.get_or_404(id)
    equipamento.em_manutencao = False
    equipamento.data_retirada = None
    db.session.commit()
    flash('Manutenção concluída com sucesso!', 'success')
    return redirect(url_for('lista_manutencoes'))

@app.route('/equipamento/<int:id>/termo/imprimir')
def imprimir_termo(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    equipamento = Equipamento.query.get_or_404(id)
    if not equipamento.termo_path:
        flash('Nenhum termo disponível para impressão', 'warning')
        return redirect(url_for('visualizar_equipamento', id=id))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], equipamento.termo_path, as_attachment=False)

@app.route('/equipamento/<int:id>/termo-devolucao/imprimir')
def imprimir_termo_devolucao(id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    equipamento = Equipamento.query.get_or_404(id)
    if not equipamento.termo_devolucao_path:
        flash('Nenhum termo de devolução disponível', 'warning')
        return redirect(url_for('visualizar_equipamento', id=id))
    
    return send_from_directory(app.config['UPLOAD_FOLDER'], equipamento.termo_devolucao_path, as_attachment=False)

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