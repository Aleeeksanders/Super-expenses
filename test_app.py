import unittest
from flask import Flask, session
from app import app
import sqlite3
import os

class AddCardRouteTestCase(unittest.TestCase):
    def setUp(self):
        # Configuración de la aplicación para pruebas
        app.config['TESTING'] = True
        app.config['SECRET_KEY'] = 'test_secret_key'
        self.app = app.test_client()
        self._ctx = app.app_context()
        self._ctx.push()

        # Configuración de la base de datos de prueba en una ruta relativa
        self.test_db = 'test_expenses.db'
        self.conn = sqlite3.connect(self.test_db)
        self.c = self.conn.cursor()
        self.c.execute("DROP TABLE IF EXISTS cards")
        self.c.execute("""
            CREATE TABLE cards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                name TEXT,
                balance REAL,
                source TEXT,
                card_type TEXT
            )
        """)
        self.conn.commit()
        
        # Simulación de un usuario en sesión
        with self.app.session_transaction() as sess:
            sess['user_id'] = 1
            sess['username'] = 'test_user'
            sess['role'] = 'user'

    def tearDown(self):
        # Cerrar la conexión y limpiar la base de datos de prueba
        self.conn.close()
        if os.path.exists(self.test_db):
            os.remove(self.test_db)
        self._ctx.pop()

    def test_add_card(self):
        # Datos del formulario de prueba
        data = {
            'name': 'Test Card',
            'balance': '5000',
            'source': 'Bank',
            'card_type': 'Debit'
        }
        
        # Simular el envío del formulario
        response = self.app.post('/add_card', data=data, follow_redirects=True)
        
        # Verificar si la tarjeta se agrega correctamente a la base de datos
        self.c.execute("SELECT * FROM cards WHERE name = ?", (data['name'],))
        card = self.c.fetchone()
        
        if card is None:
            print("La tarjeta no se agregó a la base de datos")  # Depuración
        else:
            print("Tarjeta agregada:", card)  # Depuración

        self.assertIsNotNone(card)
        self.assertEqual(card[2], data['name'])
        self.assertEqual(card[3], float(data['balance']))
        self.assertEqual(card[4], data['source'])
        self.assertEqual(card[5], data['card_type'])
        
        # Verificar la respuesta y los mensajes flash
        self.assertIn(b'Card added successfully.', response.data)

if __name__ == '__main__':
    unittest.main()
