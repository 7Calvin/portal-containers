from flask import Flask, render_template, redirect, url_for, request, session
from kubernetes import client, config
import psycopg2
import os
from kubernetes.client.exceptions import ApiException

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Configuração Kubernetes
config.load_incluster_config()
k8s_core = client.CoreV1Api()
k8s_networking = client.NetworkingV1Api()


def get_db_conn():
    return psycopg2.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASS"),
        dbname=os.getenv("DB_NAME")
    )


def verify_user(username, password):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT username, is_admin FROM users WHERE username=%s AND password=%s", (username, password))
    result = cur.fetchone()
    cur.close()
    conn.close()
    return result


def delete_if_exists(resource_type, name, namespace):
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
    namespace = "default"

    # Apaga recursos existentes, se houver
    delete_if_exists("Pod", pod_name, namespace)
    delete_if_exists("Service", service_name, namespace)
    delete_if_exists("Ingress", ingress_name, namespace)

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
    k8s_core.create_namespaced_pod(namespace=namespace, body=pod)

    service = client.V1Service(
        metadata=client.V1ObjectMeta(name=service_name),
        spec=client.V1ServiceSpec(
            selector={"app": pod_name},
            ports=[client.V1ServicePort(port=80, target_port=80)]
        )
    )
    k8s_core.create_namespaced_service(namespace=namespace, body=service)

    from kubernetes.client import (
        V1Ingress, V1IngressSpec, V1IngressRule, V1HTTPIngressRuleValue,
        V1HTTPIngressPath, V1IngressBackend, V1ServiceBackendPort, V1IngressServiceBackend,
        V1ObjectMeta
    )

    ingress = V1Ingress(
        metadata=V1ObjectMeta(
            name=ingress_name,
            annotations={"traefik.ingress.kubernetes.io/router.entrypoints": "web"}
        ),
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
    k8s_networking.create_namespaced_ingress(namespace=namespace, body=ingress)


@app.route('/')
def home():
    if 'username' in session:
        if session.get('is_admin'):
            pods = k8s_core.list_namespaced_pod(namespace="default")
            return render_template('admin.html', pods=pods.items)
        return render_template('dashboard.html', username=session['username'])
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    user = verify_user(username, password)
    if user:
        session['username'] = user[0]
        session['is_admin'] = user[1]
        return redirect(url_for('home'))
    return "Invalid login", 401

@app.route('/start_browser')
def start_browser():
    if 'username' not in session:
        return redirect(url_for('home'))
    user = session['username']
    create_browser_pod(user)
    return redirect(f"http://{user}.portal.local")

@app.route('/create_user', methods=['POST'])
def create_user():
    if not session.get('is_admin'):
        return "Não autorizado", 403

    username = request.form['username']
    password = request.form['password']
    is_admin = 'is_admin' in request.form

    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (username, password, is_admin) VALUES (%s, %s, %s)",
        (username, password, is_admin)
    )
    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for('home'))

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
