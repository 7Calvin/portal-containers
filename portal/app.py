from flask import Flask, render_template, redirect, url_for, request, session, abort, flash, jsonify
from kubernetes import client, config
import psycopg2
from psycopg2.errors import UniqueViolation
import os
from kubernetes.client.exceptions import ApiException

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuração Kubernetes
config.load_incluster_config()
NAMESPACE = "portal"
k8s_core = client.CoreV1Api()
k8s_networking = client.NetworkingV1Api()


def get_db_conn():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        dbname=os.getenv("DB_NAME")
    )


def get_all_users():
    """Retorna lista de dicionários {'username': ..., 'is_admin': ...} para todos os usuários"""
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, is_admin FROM users")
    rows = cur.fetchall()
    cur.close()
    conn.close()
    return [{'username': u, 'is_admin': a} for u, a in rows]


def verify_user(username, password):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, is_admin FROM users WHERE username=%s AND password=%s", (username, password))
    result = cur.fetchone()
    cur.close()
    conn.close()
    return result


def delete_if_exists(resource_type, name, namespace=NAMESPACE):
    try:
        if resource_type == "Pod":
            k8s_core.delete_namespaced_pod(name=name, namespace=namespace)
        elif resource_type == "Service":
            k8s_core.delete_namespaced_service(name=name, namespace=namespace)
        elif resource_type == "Ingress":
            k8s_networking.delete_namespaced_ingress(name=name, namespace=namespace)
        print(f"{resource_type} '{name}' deletado antes de recriar.")
    except ApiException as e:
        if e.status == 404:
            print(f"{resource_type} '{name}' não encontrado, prosseguindo com criação.")
        else:
            print(f"[ERRO] Falha ao deletar {resource_type} '{name}': {e.body}")
            raise


def create_browser_pod(user_id):
    pod_name = f"browser-{user_id}"
    service_name = pod_name
    ingress_name = pod_name

    # Apaga recursos existentes
    delete_if_exists("Pod", pod_name)
    delete_if_exists("Service", service_name)
    delete_if_exists("Ingress", ingress_name)

    pod = client.V1Pod(
        metadata=client.V1ObjectMeta(name=pod_name, labels={"app": pod_name}),
        spec=client.V1PodSpec(
            containers=[
                client.V1Container(
                    name="browser",
                    image="dorowu/ubuntu-desktop-lxde-vnc",
                    ports=[client.V1ContainerPort(container_port=80)],
                    env=[client.V1EnvVar(name="VNC_PASSWORD", value="abc123")]
                )
            ]
        )
    )
    k8s_core.create_namespaced_pod(namespace=NAMESPACE, body=pod)

    svc = client.V1Service(
        metadata=client.V1ObjectMeta(name=service_name),
        spec=client.V1ServiceSpec(
            selector={"app": pod_name},
            ports=[client.V1ServicePort(port=80, target_port=80)]
        )
    )
    k8s_core.create_namespaced_service(namespace=NAMESPACE, body=svc)

    # Ingress Traefik
    from kubernetes.client import (
        V1Ingress, V1IngressSpec, V1IngressRule, V1HTTPIngressRuleValue,
        V1HTTPIngressPath, V1IngressBackend, V1ServiceBackendPort, V1IngressServiceBackend,
        V1ObjectMeta
    )
    ing = V1Ingress(
        metadata=V1ObjectMeta(name=ingress_name, annotations={
            "traefik.ingress.kubernetes.io/router.entrypoints": "web"
        }),
        spec=V1IngressSpec(
            rules=[
                V1IngressRule(
                    host=f"{user_id}.portal.local",
                    http=V1HTTPIngressRuleValue(
                        paths=[
                            V1HTTPIngressPath(
                                path="/",
                                path_type="Prefix",
                                backend=V1IngressBackend(
                                    service=V1IngressServiceBackend(
                                        name=service_name,
                                        port=V1ServiceBackendPort(number=80)
                                    )
                                )
                            )
                        ]
                    )
                )
            ]
        )
    )
    k8s_networking.create_namespaced_ingress(namespace=NAMESPACE, body=ing)


@app.route('/')
def home():
    # login
    if 'username' not in session:
        return render_template('login.html')

    # admin view
    if session.get('is_admin'):
        pods = [p for p in k8s_core.list_namespaced_pod(NAMESPACE).items if p.metadata.name.startswith('browser-')]
        users = get_all_users()
        return render_template('admin.html', pods=pods, users=users)

    # user view
    user = session['username']
    pods = k8s_core.list_namespaced_pod(NAMESPACE, label_selector=f'app=browser-{user}').items
    pod_exists = len(pods) > 0
    pod_ip = pods[0].status.pod_ip if pod_exists else None
    return render_template('dashboard.html', pod_exists=pod_exists, pod_ip=pod_ip)

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = verify_user(username, password)
    if not user:
        flash("Credenciais inválidas", "error")
        return redirect(url_for('home'))
    session['username'], session['is_admin'] = user
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

# API para JS
@app.route('/check_browser')
def check_browser():
    if 'username' not in session:
        abort(403)
    u = session['username']
    exists = any(p.metadata.name == f"browser-{u}" for p in k8s_core.list_namespaced_pod(NAMESPACE).items)
    return jsonify({'exists': exists})

@app.route('/start_browser')
def start_browser():
    user = session.get('username') or ''
    if not user:
        return redirect(url_for('home'))
    if any(p.metadata.name == f"browser-{user}" for p in k8s_core.list_namespaced_pod(NAMESPACE).items):
        return redirect(f"http://{user}.portal.local")
    create_browser_pod(user)
    return redirect(f"http://{user}.portal.local")

@app.route('/delete_pod/<pod_name>')
def delete_pod(pod_name):
    if not session.get('is_admin'):
        abort(403)
    delete_if_exists("Pod", pod_name)
    delete_if_exists("Service", pod_name)
    delete_if_exists("Ingress", pod_name)
    flash(f"Pod '{pod_name}' excluído.", "success")
    return redirect(url_for('home'))

@app.route('/create_user', methods=['POST'])
def create_user():
    if not session.get('is_admin'):
        abort(403)
    username = request.form['username']
    password = request.form['password']
    is_admin = 'is_admin' in request.form
    conn = get_db_conn()
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password, is_admin) VALUES (%s,%s,%s)",
                    (username, password, is_admin))
        conn.commit()
        flash("Usuário criado com sucesso!", "success")
    except UniqueViolation:
        conn.rollback()
        flash("Já existe um usuário com esse nome.", "error")
    finally:
        cur.close()
        conn.close()
    return redirect(url_for('home'))

@app.route('/delete_user/<username>')
def delete_user(username):
    if not session.get('is_admin'):
        abort(403)
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE username=%s", (username,))
    conn.commit()
    cur.close()
    conn.close()
    flash(f"Usuário '{username}' excluído.", "success")
    return redirect(url_for('home'))

@app.route('/edit_user/<username>', methods=['POST'])
def edit_user(username):
    if not session.get('is_admin'):
        abort(403)
    new_pw = request.form.get('new_password')
    if not new_pw:
        abort(400)
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("UPDATE users SET password=%s WHERE username=%s", (new_pw, username))
    conn.commit()
    cur.close()
    conn.close()
    flash(f"Senha de '{username}' atualizada.", "success")
    return ('', 204)

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
