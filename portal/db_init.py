import psycopg2
import os

host = os.getenv("DB_HOST")
user = os.getenv("DB_USER")
password = os.getenv("DB_PASS")
dbname = os.getenv("DB_NAME")

conn = psycopg2.connect(host=host, user=user, password=password, dbname=dbname)
cursor = conn.cursor()

# Cria tabela users se não existir
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    );
""")

# Garante coluna is_admin
cursor.execute("""
    ALTER TABLE users
    ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;
""")

# Insere admin padrão (ignora se já existir)
cursor.execute("""
    INSERT INTO users (username, password, is_admin)
    VALUES (%s, %s, TRUE)
    ON CONFLICT (username) DO UPDATE SET is_admin = TRUE;
""", ('admin', 'admin123'))

conn.commit()
cursor.close()
conn.close()

print("Banco inicializado com sucesso (tabela, coluna is_admin e usuário admin).")
