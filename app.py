from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, DateField, IntegerField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo, Optional, NumberRange
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from functools import wraps
import traceback

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Lista de categorías
categories = ['Casa', 'Casa Adicionales', 'Comida Oficina', 'Gastos Necesarios Personales', 'Gastos Free', 'Prestado']

# Formularios
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=35)])
    confirm = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    initial_bank = SelectField('Banco Inicial', choices=[
        ('Mercado Pago', 'Mercado Pago'),
        ('Tenpo', 'Tenpo'),
        ('MACH', 'MACH'),
        ('BCI', 'BCI'),
        ('BICE', 'BICE'),
        ('Banco Falabella', 'Banco Falabella'),
        ('Banco Estado', 'Banco Estado'),
        ('Banco de Chile', 'Banco de Chile'),
        ('Banco Edwards', 'Banco Edwards'),
        ('Scotiabank', 'Scotiabank'),
        ('Santander', 'Santander'),
        ('Banco Internacional', 'Banco Internacional')
    ], validators=[DataRequired()])

class ExpenseForm(FlaskForm):
    date = DateField('Fecha', format='%Y-%m-%d', validators=[DataRequired()])
    description = StringField('Descripción', validators=[DataRequired()])
    amount = IntegerField('Monto', validators=[DataRequired(), NumberRange(min=0, message='El monto debe ser un valor positivo')])
    category = SelectField('Categoría', choices=[(cat, cat) for cat in categories], validators=[DataRequired()])
    payment_method = SelectField('Método de Pago', validators=[DataRequired()])
    card = SelectField('Tarjeta', choices=[], validators=[Optional()])
    return_date = DateField('Fecha de Devolución', format='%Y-%m-%d', validators=[Optional()])

    def validate(self):
        if not FlaskForm.validate(self):
            return False
        if self.category.data == 'Prestado' and not self.return_date.data:
            self.return_date.errors.append('Fecha de Devolución es requerida para la categoría Prestado.')
            return False
        return True

class BudgetForm(FlaskForm):
    total_budget = IntegerField('Presupuesto Total', validators=[DataRequired(), NumberRange(min=0, message='El presupuesto debe ser un valor positivo')])

class CardForm(FlaskForm):
    name = SelectField('Nombre de la Tarjeta', choices=[
        ('Mercado Pago', 'Mercado Pago'),
        ('Tenpo', 'Tenpo'),
        ('MACH', 'MACH'),
        ('BCI', 'BCI'),
        ('BICE', 'BICE'),
        ('Banco Falabella', 'Banco Falabella'),
        ('Banco Estado', 'Banco Estado'),
        ('Banco de Chile', 'Banco de Chile'),
        ('Banco Edwards', 'Banco Edwards'),
        ('Scotiabank', 'Scotiabank'),
        ('Santander', 'Santander'),
        ('Banco Internacional', 'Banco Internacional')
    ], validators=[DataRequired()])
    balance = IntegerField('Saldo Inicial', validators=[DataRequired(), NumberRange(min=0, message='El saldo debe ser un valor positivo')])
    source = SelectField('Origen del Saldo', choices=[('propio', 'Saldo Propio'), ('presupuesto', 'Restar del Presupuesto Principal')], validators=[DataRequired()])
    card_type = SelectField('Tipo de Tarjeta', choices=[('debito', 'Débito'), ('credito', 'Crédito')], validators=[DataRequired()])

# Database Functions
def get_db_connection():
    conn = sqlite3.connect('expenses.db')
    conn.row_factory = sqlite3.Row
    return conn

def get_user_by_username(username):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    return user

def add_user(username, password, initial_bank, role='user'):
    hashed_password = generate_password_hash(password)
    conn = get_db_connection()
    # Insert user
    conn.execute('INSERT INTO users (username, password, role, total_budget, initial_bank) VALUES (?, ?, ?, 1000000, ?)', 
                 (username, hashed_password, role, initial_bank))
    # Get the newly created user's ID
    user_id = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()['id']
    # Insert the initial bank card linked to the total budget
    conn.execute('INSERT INTO cards (user_id, name, balance, card_type) VALUES (?, ?, ?, ?)', 
                 (user_id, initial_bank, 1000000, 'debito'))
    conn.commit()
    conn.close()


def add_expense(user_id, date, description, amount, category, payment_method, return_date, card_id=None):
    conn = get_db_connection()
    conn.execute('INSERT INTO expenses (user_id, date, description, amount, category, payment_method, return_date, card_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
                 (user_id, date, description, amount, category, payment_method, return_date, card_id))
    conn.commit()
    conn.close()

def get_card_by_id(card_id):
    conn = get_db_connection()
    card = conn.execute('SELECT * FROM cards WHERE id = ?', (card_id,)).fetchone()
    conn.close()
    return card

def delete_expense(expense_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM expenses WHERE id = ?', (expense_id,))
    conn.commit()
    conn.close()

def delete_user(user_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
    conn.commit()
    conn.close()

def update_total_budget(user_id, total_budget):
    conn = get_db_connection()
    conn.execute('UPDATE users SET total_budget = ? WHERE id = ?', (total_budget, user_id))
    conn.commit()
    conn.close()

def get_expenses_by_user(user_id):
    conn = get_db_connection()
    query = '''
    SELECT e.*, c.name AS card_name
    FROM expenses e
    LEFT JOIN cards c ON e.card_id = c.id
    WHERE e.user_id = ?
    '''
    expenses = conn.execute(query, (user_id,)).fetchall()
    conn.close()
    return expenses


def get_all_users():
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return users

def get_payment_methods():
    conn = get_db_connection()
    methods = conn.execute('SELECT id, name FROM payment_methods').fetchall()
    conn.close()
    return [{'id': method['id'], 'name': method['name']} for method in methods]

def get_cards_by_user(user_id):
    conn = get_db_connection()
    cards = conn.execute('SELECT * FROM cards WHERE user_id = ?', (user_id,)).fetchall()
    conn.close()
    return cards

def add_card(user_id, name, balance, card_type, source):
    conn = get_db_connection()
    conn.execute('INSERT INTO cards (user_id, name, balance, card_type) VALUES (?, ?, ?, ?)', (user_id, name, balance, card_type))
    conn.commit()
    if source == 'presupuesto':
        user = get_user_by_id(user_id)
        new_budget = user['total_budget'] - balance
        conn.execute('UPDATE users SET total_budget = ? WHERE id = ?', (new_budget, user_id))
        conn.commit()
    conn.close()

def withdraw_cash(user_id, amount):
    conn = get_db_connection()
    try:
        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user['total_budget'] < amount:
            raise Exception('Saldo insuficiente en el presupuesto total.')
        
        new_total_budget = user['total_budget'] - amount
        new_cash_balance = user['cash_balance'] + amount
        
        conn.execute('UPDATE users SET total_budget = ?, cash_balance = ? WHERE id = ?', (new_total_budget, new_cash_balance, user_id))
        conn.commit()
        print("Cash withdrawn successfully.")
    except Exception as e:
        conn.rollback()
        print(f"An error occurred: {e}")
        raise
    finally:
        conn.close()


def update_card_balance(card_id, balance):
    conn = get_db_connection()
    conn.execute('UPDATE cards SET balance = ? WHERE id = ?', (balance, card_id))
    conn.commit()
    conn.close()

# Decorador para verificar la autenticación
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Decorador para verificar si el usuario es administrador
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = get_user_by_id(session['user_id'])
        if user['role'] != 'admin':
            flash('You do not have permission to access this page.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def withdraw_from_card(user_id, card_id, amount):
    conn = get_db_connection()
    try:
        card = conn.execute('SELECT * FROM cards WHERE id = ? AND user_id = ?', (card_id, user_id)).fetchone()
        if card['balance'] < amount:
            raise Exception('Saldo insuficiente en la tarjeta.')
        
        new_balance = card['balance'] - amount
        conn.execute('UPDATE cards SET balance = ? WHERE id = ?', (new_balance, card_id))

        user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        new_cash_balance = user['cash_balance'] + amount
        conn.execute('UPDATE users SET cash_balance = ? WHERE id = ?', (new_cash_balance, user_id))

        conn.commit()
        print("Cash withdrawn from card successfully.")
    except Exception as e:
        conn.rollback()
        print(f"An error occurred: {e}")
        raise
    finally:
        conn.close()

# Routes
@app.route('/')
def index():
    print("Redirecting to login")
    session.pop('user_id', None)  # Cerrar sesión en cada carga de la página
    return redirect(url_for('login'))

@app.route('/withdraw_cash', methods=['POST'])
@login_required
def withdraw_cash_route():
    amount = request.form.get('amount')
    if not amount:
        flash('No se ha especificado un monto.')
        return redirect(url_for('dashboard'))
    
    try:
        amount = int(amount)
        if amount <= 0:
            flash('El monto debe ser un valor positivo.')
            return redirect(url_for('dashboard'))

        user_id = session['user_id']
        withdraw_cash(user_id, amount)
        flash('Dinero girado satisfactoriamente.')
    except Exception as e:
        print("An error occurred while withdrawing cash:")
        print(traceback.format_exc())
        flash(f'Error al girar dinero en efectivo: {str(e)}')

    return redirect(url_for('dashboard'))

# Ruta para girar dinero desde una tarjeta
@app.route('/withdraw_from_card', methods=['POST'])
@login_required
def withdraw_from_card_route():
    card_id = request.form.get('card_id')
    amount = request.form.get('amount')
    if not card_id or not amount:
        flash('Debe especificar una tarjeta y un monto.')
        return redirect(url_for('dashboard'))
    
    try:
        amount = int(amount)
        if amount <= 0:
            flash('El monto debe ser un valor positivo.')
            return redirect(url_for('dashboard'))

        user_id = session['user_id']
        withdraw_from_card(user_id, card_id, amount)
        flash('Dinero girado satisfactoriamente desde la tarjeta.')
    except Exception as e:
        print("An error occurred while withdrawing cash from card:")
        print(traceback.format_exc())
        flash(f'Error al girar dinero desde la tarjeta: {str(e)}')

    return redirect(url_for('dashboard'))

@app.route('/add_balance/<int:card_id>', methods=['POST'])
@login_required
def add_balance_to_card(card_id):
    amount = request.form.get('amount')
    if not amount:
        flash('No se ha especificado un monto.')
        return redirect(url_for('dashboard'))
    
    try:
        amount = int(amount)
        if amount <= 0:
            flash('El monto debe ser un valor positivo.')
            return redirect(url_for('dashboard'))

        conn = get_db_connection()
        card = conn.execute('SELECT * FROM cards WHERE id = ?', (card_id,)).fetchone()
        if card:
            new_balance = card['balance'] + amount
            conn.execute('UPDATE cards SET balance = ? WHERE id = ?', (new_balance, card_id))
            conn.commit()
            conn.close()
            flash('Saldo añadido satisfactoriamente.')
        else:
            flash('Tarjeta no encontrada.')
    except Exception as e:
        print("An error occurred while adding balance to the card:")
        print(traceback.format_exc())
        flash(f'Error al añadir saldo a la tarjeta: {str(e)}')

    return redirect(url_for('dashboard'))

@app.route('/delete_card/<int:card_id>', methods=['POST'])
@login_required
def delete_card(card_id):
    try:
        conn = get_db_connection()
        conn.execute('DELETE FROM cards WHERE id = ?', (card_id,))
        conn.commit()
        conn.close()
        flash('Tarjeta eliminada satisfactoriamente.')
    except Exception as e:
        print("An error occurred while deleting the card:")
        print(traceback.format_exc())
        flash(f'Error al eliminar la tarjeta: {str(e)}')
    return redirect(url_for('dashboard'))

@app.route('/transfer_balance', methods=['POST'])
@login_required
def transfer_balance():
    from_card_id = request.form.get('from_card_id')
    to_card_id = request.form.get('to_card_id')
    amount = request.form.get('amount')
    
    if not from_card_id or not to_card_id or not amount:
        flash('Debe especificar todas las tarjetas y el monto.')
        return redirect(url_for('dashboard'))
    
    try:
        amount = int(amount)
        if amount <= 0:
            flash('El monto debe ser un valor positivo.')
            return redirect(url_for('dashboard'))
        
        conn = get_db_connection()
        
        # Get balances of both cards
        from_card = conn.execute('SELECT * FROM cards WHERE id = ?', (from_card_id,)).fetchone()
        to_card = conn.execute('SELECT * FROM cards WHERE id = ?', (to_card_id,)).fetchone()
        
        if from_card['balance'] <= 0:
            flash('Saldo insuficiente en la tarjeta de origen.')
            conn.close()
            return redirect(url_for('dashboard'))
        
        if from_card['balance'] < amount:
            flash('Saldo insuficiente en la tarjeta de origen.')
            conn.close()
            return redirect(url_for('dashboard'))
        
        # Update balances
        new_from_balance = from_card['balance'] - amount
        new_to_balance = to_card['balance'] + amount
        
        conn.execute('UPDATE cards SET balance = ? WHERE id = ?', (new_from_balance, from_card_id))
        conn.execute('UPDATE cards SET balance = ? WHERE id = ?', (new_to_balance, to_card_id))
        conn.commit()
        conn.close()
        
        flash('Transferencia realizada satisfactoriamente.')
    except Exception as e:
        print("An error occurred while transferring balance between cards:")
        print(traceback.format_exc())
        flash(f'Error al transferir saldo entre tarjetas: {str(e)}')

    return redirect(url_for('dashboard'))


@app.route('/dashboard')
@login_required
def dashboard():
    print("Accessing dashboard")
    user_id = session['user_id']
    user = get_user_by_id(user_id)
    expenses = get_expenses_by_user(user_id)
    total_budget = user['total_budget']
    cash_balance = user['cash_balance']
    
    conn = get_db_connection()
    initial_card = conn.execute('SELECT * FROM cards WHERE user_id = ? AND name = ?', (user_id, user['initial_bank'])).fetchone()
    conn.close()
    
    if not initial_card:
        flash('No se encontró la tarjeta del banco inicial. Por favor, contacte al administrador.')
        current_fund = 0
    else:
        current_fund = initial_card['balance']
    
    form = ExpenseForm()
    budget_form = BudgetForm()
    card_form = CardForm()
    payment_methods = get_payment_methods()
    form.payment_method.choices = [(method['name'], method['name']) for method in payment_methods] + [('Efectivo', 'Efectivo')]
    form.card.choices = [(card['id'], card['name']) for card in get_cards_by_user(user_id)]
    cards = get_cards_by_user(user_id)
    print(f"User {user['username']} accessed the dashboard.")
    return render_template('index.html', user=user, expenses=expenses, current_fund=current_fund, cash_balance=cash_balance, categories=categories, form=form, budget_form=budget_form, card_form=card_form, cards=cards)

@app.route('/admin')
@admin_required
def admin_dashboard():
    users = get_all_users()
    return render_template('admin.html', users=users)

@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user_route(user_id):
    try:
        delete_user(user_id)
        flash('Usuario eliminado satisfactoriamente.')
    except Exception as e:
        print("An error occurred while deleting the user:")
        print(traceback.format_exc())
        flash(f'There was an error deleting the user: {str(e)}')
    return redirect(url_for('admin_dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        print("Already logged in, redirecting to dashboard")
        return redirect(url_for('dashboard'))

    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        user = get_user_by_username(username)
        if user and check_password_hash(user['password'], password):
            session['user_id'] = user['id']
            print(f"User {username} logged in. Redirecting to dashboard")
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.')
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    form = RegisterForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        initial_bank = form.initial_bank.data
        if get_user_by_username(username):
            flash('Username already exists.')
        else:
            add_user(username, password, initial_bank)
            flash('Registration successful. Please log in.')
            return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/add', methods=['POST'])
@login_required
def add():
    form = ExpenseForm(request.form)
    form.payment_method.choices = [(method['name'], method['name']) for method in get_payment_methods()] + [('Efectivo', 'Efectivo')]
    form.card.choices = [(card['id'], card['name']) for card in get_cards_by_user(session['user_id'])]

    print("Form data received.")
    print(f"Form content: {request.form}")
    if form.validate():
        try:
            user_id = session.get('user_id')
            print(f"user_id from session: {user_id}")

            if not user_id:
                raise Exception("No user_id in session")

            date = form.date.data.strftime('%Y-%m-%d')
            description = form.description.data
            amount = int(form.amount.data)  # Asegurarse de que el monto es un entero
            category = form.category.data
            payment_method = form.payment_method.data
            card_id = form.card.data if form.card.data else None
            return_date = form.return_date.data.strftime('%Y-%m-%d') if form.return_date.data else None

            # Debugging
            print(f"Adding expense: user_id={user_id}, date={date}, description={description}, amount={amount}, category={category}, payment_method={payment_method}, card_id={card_id}, return_date={return_date}")

            conn = get_db_connection()
            user = get_user_by_id(user_id)
            initial_card = conn.execute('SELECT * FROM cards WHERE user_id = ? AND name = ?', (user_id, user['initial_bank'])).fetchone()
            if not initial_card:
                flash('No se encontró la tarjeta del banco inicial.')
                conn.close()
                return redirect(url_for('dashboard'))

            if payment_method == 'Efectivo':
                if user['cash_balance'] <= 0:
                    flash('Saldo insuficiente en efectivo.')
                    conn.close()
                    return redirect(url_for('dashboard'))
                if user['cash_balance'] < amount:
                    flash('Saldo insuficiente en efectivo.')
                    conn.close()
                    return redirect(url_for('dashboard'))
                new_balance = user['cash_balance'] - amount
                conn.execute('UPDATE users SET cash_balance = ? WHERE id = ?', (new_balance, user_id))
            elif payment_method in ['Tarjeta de Débito', 'Tarjeta de Crédito'] and card_id:
                card = get_card_by_id(card_id)
                if card['balance'] <= 0:
                    flash('Saldo insuficiente en la tarjeta seleccionada.')
                    conn.close()
                    return redirect(url_for('dashboard'))
                if card['balance'] < amount:
                    flash('Saldo insuficiente en la tarjeta seleccionada.')
                    conn.close()
                    return redirect(url_for('dashboard'))
                new_balance = card['balance'] - amount
                update_card_balance(card_id, new_balance)
            elif payment_method == 'Tarjeta de Débito' and card_id == initial_card['id']:
                if initial_card['balance'] <= 0:
                    flash('Saldo insuficiente en la tarjeta del banco inicial.')
                    conn.close()
                    return redirect(url_for('dashboard'))
                if initial_card['balance'] < amount:
                    flash('Saldo insuficiente en la tarjeta del banco inicial.')
                    conn.close()
                    return redirect(url_for('dashboard'))
                new_balance = initial_card['balance'] - amount
                update_card_balance(initial_card['id'], new_balance)

            add_expense(user_id, date, description, amount, category, payment_method, return_date, card_id)
            print(f"Expense added: {description} - {amount}")

            conn.commit()
            conn.close()
            flash('Gasto añadido satisfactoriamente.')
        except Exception as e:
            print("An error occurred while adding the expense:")
            print(traceback.format_exc())
            flash(f'There was an error adding the expense: {str(e)}')

        return redirect(url_for('dashboard'))
    else:
        print("Form validation failed")
        print(form.errors)  # Imprimir errores de validación
        flash('There was an error with your submission.')
    return redirect(url_for('dashboard'))




@app.route('/delete/<int:expense_id>', methods=['POST'])
@login_required
def delete(expense_id):
    try:
        delete_expense(expense_id)
        flash('Gasto eliminado satisfactoriamente.')
    except Exception as e:
        print("An error occurred while deleting the expense:")
        print(traceback.format_exc())
        flash(f'There was an error deleting the expense: {str(e)}')
    return redirect(url_for('dashboard'))

@app.route('/add_card', methods=['POST'])
@login_required
def add_card_route():
    form = CardForm(request.form)
    if form.validate_on_submit():
        user_id = session['user_id']
        name = form.name.data
        balance = form.balance.data
        source = form.source.data
        card_type = form.card_type.data
        try:
            add_card(user_id, name, balance, card_type, source)
            flash('Tarjeta añadida satisfactoriamente.')
        except Exception as e:
            print("An error occurred while adding the card:")
            print(traceback.format_exc())
            flash(f'Error al añadir la tarjeta: {str(e)}')
    else:
        print("Form validation failed")
        print(form.errors)  # Imprimir errores de validación
        flash('There was an error with your submission.')
    return redirect(url_for('dashboard'))

@app.route('/update_budget', methods=['POST'])
@login_required
def update_budget():
    form = BudgetForm(request.form)
    if form.validate():
        try:
            user_id = session.get('user_id')
            total_budget = int(form.total_budget.data)  # Asegurarse de que el presupuesto es un entero
            # Update the total budget
            conn = get_db_connection()
            conn.execute('UPDATE users SET total_budget = ? WHERE id = ?', (total_budget, user_id))
            
            # Update the initial bank card balance
            user = get_user_by_id(user_id)
            initial_card = conn.execute('SELECT * FROM cards WHERE user_id = ? AND name = ?', (user_id, user['initial_bank'])).fetchone()
            if not initial_card:
                flash('No se encontró la tarjeta del banco inicial.')
                return redirect(url_for('dashboard'))
            
            conn.execute('UPDATE cards SET balance = ? WHERE id = ?', (total_budget, initial_card['id']))
            
            conn.commit()
            conn.close()
            
            flash('Presupuesto actualizado satisfactoriamente.')
        except Exception as e:
            print("An error occurred while updating the budget:")
            print(traceback.format_exc())
            flash(f'There was an error updating the budget: {str(e)}')
    else:
        print("Form validation failed")
        print(form.errors)  # Imprimir errores de validación
        flash('There was an error with your submission.')
    return redirect(url_for('dashboard'))



@app.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id')
    user = get_user_by_id(user_id) if user_id else None
    if user:
        print(f"User {user['username']} logged out.")
    session.pop('user_id', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
   app.run(debug=True)
#if __name__ == '__main__':
 #   from waitress import serve
  #  serve(app, host='0.0.0.0', port=8080)
