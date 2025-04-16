from flask import Flask, render_template, request, redirect,render_template_string, url_for, flash, session
import sqlite3
import smtplib
from email.message import EmailMessage
import random
import string
from werkzeug.security import generate_password_hash, check_password_hash
import numpy as np
from datetime import datetime, timedelta
from dotenv import load_dotenv
import os

load_dotenv() 
app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
DATABASE = 'database.db'
login_attempts = {}
EMAIL_USER = os.getenv('EMAIL_USER')
EMAIL_PASS = os.getenv('EMAIL_PASS')
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///database.db')

def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS utilisateurs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            prenom TEXT NOT NULL,
            motdepasse TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL
        )
    ''')
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def envoyer_code(email_dest, code):
    email = EmailMessage()
    email['Subject'] = 'Code de récupération'
    email['From'] = EMAIL_USER
    email['To'] = email_dest
    email.set_content(f'Votre code de récupération est : {code}')

    with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
        smtp.login( EMAIL_USER , EMAIL_PASS )
        smtp.send_message(email)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        nom = request.form['nom']
        prenom = request.form['prenom']
        motdepasse = request.form['password']
        email = request.form['email']

        if len(motdepasse) < 8:
            flash('Le mot de passe doit contenir au moins 8 caractères')
        elif '@' not in email:
            flash('Un email non valide.')
        else:
            # تشفير كلمة المرور
            hashed_password = generate_password_hash(motdepasse)
            
            conn = get_db_connection()
            conn.execute('INSERT INTO utilisateurs (nom, prenom, motdepasse, email) VALUES (?, ?, ?, ?)',
                         (nom, prenom, hashed_password, email))
            conn.commit()
            conn.close()
            flash('Compte créé avec succès.')
            return redirect(url_for('index'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        motdepasse = request.form['password']
        ip_address = request.remote_addr

        if ip_address in login_attempts and login_attempts[ip_address]['attempts'] >= 5:
            last_attempt = login_attempts[ip_address]['last_attempt']
            if datetime.now() < last_attempt + timedelta(minutes=5):
                remaining_time = int((last_attempt + timedelta(minutes=5) - datetime.now()).total_seconds() / 60)
                flash(f"Trop de tentatives. Réessayez dans {remaining_time:.0f} minutes", "danger")
                return redirect(url_for('login'))
            else:
                login_attempts.pop(ip_address)

        conn = get_db_connection()
        utilisateur = conn.execute('SELECT * FROM utilisateurs WHERE email = ?', (email,)).fetchone()
        conn.close()

        if utilisateur and check_password_hash(utilisateur['motdepasse'], motdepasse):
            session['utilisateur'] = utilisateur['prenom']
            login_attempts.pop(ip_address, None) 
            return redirect(url_for('calcul_diffusion'))
        else:
            if ip_address not in login_attempts:
                login_attempts[ip_address] = {'attempts': 1, 'last_attempt': datetime.now()}
            else:
                login_attempts[ip_address]['attempts'] += 1
                login_attempts[ip_address]['last_attempt'] = datetime.now()

            flash('Email ou mot de passe incorrect.', 'danger')

    return render_template('login.html')

@app.route('/motdepasse-oublie', methods=['GET', 'POST'])
def motdepasse_oublie():
    if request.method == 'POST':
        email = request.form['email']
        code = str(random.randint(100000, 999999))
        session['code'] = code
        session['email_reset'] = email
        envoyer_code(email, code)
        return redirect(url_for('code_verification'))
    return render_template('forgot_password.html')

@app.route('/code_verification', methods=['GET', 'POST'])
def code_verification():
    if 'email_reset' not in session:
        return redirect(url_for('motdepasse_oublie'))
    
    if request.method == 'POST':
        code_utilisateur = request.form['code']
        if code_utilisateur == session.get('code'):
            flash('Code vérifié avec succès', 'success')
            return redirect(url_for('changer_motdepasse'))
        else:
            flash('Code incorrect', 'danger')
    return render_template('code_verification.html')

@app.route('/changer-motdepasse', methods=['GET', 'POST'])
def changer_motdepasse():
    if 'email_reset' not in session:
        return redirect(url_for('motdepasse_oublie'))
    
    if request.method == 'POST':
        nouveau_motdepasse = request.form['nouveau_motdepasse']
        confirmation = request.form['confirmation']
        
        if nouveau_motdepasse != confirmation:
            flash('Les mots de passe ne correspondent pas', 'danger')
            return render_template('changer_motdepasse.html')
        
        if len(nouveau_motdepasse) < 8:
            flash('Le mot de passe doit contenir au moins 8 caractères', 'danger')
            return render_template('changer_motdepasse.html')
        
        if update_user_password(session['email_reset'], nouveau_motdepasse):
            flash('Votre mot de passe a été changé avec succès', 'success')
            session.pop('email_reset', None)  # إزالة البريد الإلكتروني من الجلسة
            return redirect(url_for('login'))
        else:
            flash('Une erreur est survenue lors de la mise à jour du mot de passe', 'danger')
            return render_template('changer_motdepasse.html')
    
    return render_template('changer_motdepasse.html')

def update_user_password(email, nouveau_motdepasse):
    try:
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        
        # التحقق من وجود البريد الإلكتروني في الجدول الصحيح
        cursor.execute("SELECT email FROM utilisateurs WHERE email = ?", (email,))
        utilisateur = cursor.fetchone()
        
        if not utilisateur:
            conn.close()
            return False
        
        # تشفير كلمة المرور الجديدة
        hashed_password = generate_password_hash(nouveau_motdepasse)
        
        # تحديث كلمة المرور في الجدول الصحيح
        cursor.execute(
            "UPDATE utilisateurs SET motdepasse = ? WHERE email = ?",
            (hashed_password, email)
        )
        
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"Error updating password: {e}")
        return False

@app.route('/calcul_diffusion', methods=['GET', 'POST'])
def calcul_diffusion():
    if 'utilisateur' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        try:
            x_A = float(request.form['x_A'])
            D_AB_0_A = float(request.form['D_AB_0_A'])
            D_AB_0_B = float(request.form['D_AB_0_B'])
            D_exp = 1.3295e-5

            if not (0 <= x_A <= 1):
                flash("La fraction molaire x_A doit être entre 0 et 1.", "danger")
                return render_template("calcul_diffusion.html")

            if D_AB_0_A <= 0 or D_AB_0_B <= 0:
                flash("Les valeurs de D_AB_0 doivent être positives.", "danger")
                return render_template("calcul_diffusion.html")

            # Constantes
            lambda_A = 1.1269
            lambda_B = 0.9725
            q_A = 1.432
            q_B = 1.4
            theta_BA = 0.612
            theta_AB = 0.261
            theta_AA = 0.388
            theta_BB = 0.739
            tau_AB = 1.0326
            tau_BA = 0.5383

            x_B = 1 - x_A
            phi_A = x_A * lambda_A / (x_A * lambda_A + x_B * lambda_B)
            phi_B = x_B * lambda_B / (x_A * lambda_A + x_B * lambda_B)

            ln_D_AB = (
                x_B * np.log(D_AB_0_A) + x_A * np.log(D_AB_0_B) +
                2 * (x_A * np.log(x_A / phi_A) + x_B * np.log(x_B / phi_B)) +
                2 * x_A * x_B * ((phi_A / x_A) * (1 - (lambda_A / lambda_B)) + (phi_B / x_B) * (1 - (lambda_B / lambda_A))) +
                (x_B * q_A) * ((1 - theta_BA**2) * np.log(tau_BA) + (1 - theta_BB**2) * tau_AB * np.log(tau_AB)) +
                (x_A * q_B) * ((1 - theta_AB**2) * np.log(tau_AB) + (1 - theta_AA**2) * tau_BA * np.log(tau_BA))
            )
            D_AB = np.exp(ln_D_AB)
            erreur = abs((D_AB - D_exp) / D_exp) * 100

            return render_template("resultat.html", D_AB=D_AB, erreur=erreur)
        except ValueError:
            flash("Veuillez entrer des valeurs numériques valides.", "danger")
        except Exception as e:
            print(f"Erreur: {e}")
            flash("Une erreur est survenue lors du calcul.", "danger")
    return render_template("calcul_diffusion.html")

@app.route('/logout')
def logout():
    session.clear()
    flash("Déconnecté avec succès", "info")
    return redirect(url_for('index'))

@app.route('/<page>')
def page_not_found(page):
    return render_template_string("<h1> sorry this page "+page+" is note found<h1>"), 404

if __name__ == '__main__':
    init_db()
    app.run(debug=True)