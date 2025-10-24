#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import tempfile
import threading
import queue
import subprocess
import base64
import secrets
import string
import time
import shutil
import json
import requests
import urllib.parse

# Default editável na UI
DEFAULT_API_SERVER = "https://api.cluster.openshift.com:6443" # Mude para endereço do seu Cluster
ROUTE_DOMAIN = "apps.cluster.openshift.com" # Mude para endereço do seu Cluster
VERSAO = "1.0.0"

# ---- GUI: tenta CustomTkinter; se não, fallback para tkinter ----
try:
    import customtkinter as ctk
    GUI_LIB = "ctk"
except Exception:
    import tkinter as ctk  # type: ignore
    from tkinter import ttk, messagebox  # type: ignore
    GUI_LIB = "tk"

# ---- Dependências do K8s ----
try:
    from kubernetes import client, config
    from kubernetes.client.rest import ApiException
except Exception:
    print("Erro: instale a lib Kubernetes:  pip install kubernetes")
    sys.exit(1)

# Para silenciar warnings TLS quando usar insecure
import urllib3
from urllib3.exceptions import InsecureRequestWarning

FILEBROWSER_IMAGE = os.environ.get("FILEBROWSER_IMAGE", "filebrowser/filebrowser:latest")
APP_LABEL_KEY = "app"
SERVICE_NAME = "filebrowser-auto"
DEPLOY_NAME = "filebrowser-auto"
ROUTE_NAME = "filebrowser-auto"
SECRET_NAME = "filebrowser-credentials"
PVC_DB_NAME = "filebrowser-config"     # /database
PVC_CFG_NAME = "filebrowser-settings"  # /config
STORAGECLASS_CEPHFS = "ocs-storagecluster-cephfs"

# ----------------- Utils -----------------
def gen_password(min_len: int = 12) -> str:
    """Gera senha com letras minúsculas e maiúsculas, no mínimo min_len."""
    alphabet = string.ascii_lowercase + string.ascii_uppercase + string.digits
    while True:
        pwd = ''.join(secrets.choice(alphabet) for _ in range(min_len))
        if any(c.islower() for c in pwd) and any(c.isupper() for c in pwd):
            return pwd

def run_cmd(cmd, env=None, check=True):
    r = subprocess.run(cmd, env=env, text=True, capture_output=True)
    if check and r.returncode != 0:
        raise RuntimeError(
            f"cmd failed: {' '.join(cmd)}\nstdout:\n{r.stdout}\nstderr:\n{r.stderr}"
        )
    return r

def _exe_dir():
    # diretório do executável (ou da pasta temporária do PyInstaller)
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        return sys._MEIPASS
    return os.path.dirname(os.path.abspath(sys.argv[0]))

def find_oc():
    # 1) var de ambiente
    p = os.environ.get("OCP_OC_PATH")
    if p and os.path.exists(p):
        return p
    # 2) PATH
    ocname = "oc.exe" if os.name == "nt" else "oc"
    p = shutil.which(ocname)
    if p:
        return p
    # 3) ao lado do executável/script
    cand = os.path.join(_exe_dir(), "oc.exe" if os.name == "nt" else "oc")
    if os.path.exists(cand):
        return cand
    return None

def oauth_token_login(server: str, username: str, password: str, insecure=False) -> str:
    """
    Faz login via OAuth (openshift-challenging-client) e retorna Bearer token.
    Usado apenas se o oc.exe não estiver disponível.
    """
    auth_url = server.rstrip("/") + "/oauth/authorize?response_type=token&client_id=openshift-challenging-client"
    sess = requests.Session()
    verify = not insecure

    # 1ª ida: sem credenciais (gera o desafio)
    r = sess.get(auth_url, allow_redirects=False, verify=verify, timeout=10)
    # 2ª ida: com basic auth
    r = sess.get(auth_url, allow_redirects=False, verify=verify, auth=(username, password), timeout=10)
    loc = r.headers.get("Location", "")
    if "access_token=" not in loc:
        raise RuntimeError(f"Falha no OAuth (status={r.status_code}). Sem access_token no Location.")
    frag = urllib.parse.urlparse(loc).fragment
    qs = urllib.parse.parse_qs(frag)
    tok = qs.get("access_token", [None])[0]
    if not tok:
        raise RuntimeError("OAuth retornou sem access_token.")
    return tok

def write_minimal_kubeconfig(server: str, token: str, kcfg_path: str, insecure=False):
    cfg = {
        "apiVersion": "v1",
        "kind": "Config",
        "clusters": [{
            "name": "cluster",
            "cluster": {
                "server": server,
                "insecure-skip-tls-verify": bool(insecure)
            }
        }],
        "users": [{
            "name": "user",
            "user": {"token": token}
        }],
        "contexts": [{
            "name": "ctx",
            "context": {"cluster": "cluster", "user": "user"}
        }],
        "current-context": "ctx"
    }
    with open(kcfg_path, "w", encoding="utf-8") as f:
        json.dump(cfg, f)

def oc_login(server: str, username: str, password: str, kcfg_path: str, insecure=False):
    """
    Tenta logar com 'oc login' (usando oc.exe se presente).
    Se não houver oc, cai para OAuth e gera kubeconfig mínimo.
    """
    env = os.environ.copy()
    env["KUBECONFIG"] = kcfg_path
    oc_bin = find_oc()
    if oc_bin:
        arg_tls = "--insecure-skip-tls-verify=true" if insecure else "--insecure-skip-tls-verify=false"
        cmd = [oc_bin, "login", server, "-u", username, "-p", password, arg_tls]
        return run_cmd(cmd, env=env), env
    # Fallback: OAuth
    token = oauth_token_login(server, username, password, insecure=insecure)
    write_minimal_kubeconfig(server, token, kcfg_path, insecure=insecure)
    class _R:
        returncode = 0
        stdout = "login via OAuth (sem oc)\n"
        stderr = ""
    return _R(), env

def load_kube_from(env, insecure=False):
    """Carrega kubeconfig e ajusta verify_ssl conforme 'insecure'."""
    kcfg = env.get("KUBECONFIG")
    if not kcfg or not os.path.exists(kcfg):
        raise RuntimeError("KUBECONFIG não encontrado.")
    config.load_kube_config(config_file=kcfg)
    cfg = client.Configuration.get_default_copy()
    cfg.verify_ssl = not insecure
    if insecure:
        urllib3.disable_warnings(InsecureRequestWarning)
    client.Configuration.set_default(cfg)

def ensure_namespace_exists(core: client.CoreV1Api, ns: str):
    try:
        core.read_namespace(ns)
    except ApiException as e:
        if e.status == 404:
            raise RuntimeError(f"Namespace '{ns}' não existe.")
        raise

def ensure_pvc(core, ns, name, size, storageclass, access_modes):
    try:
        core.read_namespaced_persistent_volume_claim(name, ns)
        return
    except ApiException as e:
        if e.status != 404:
            raise
    spec = client.V1PersistentVolumeClaimSpec(
        access_modes=access_modes,
        resources=client.V1ResourceRequirements(requests={"storage": size}),
        storage_class_name=storageclass
    )
    meta = client.V1ObjectMeta(name=name, namespace=ns)
    pvc = client.V1PersistentVolumeClaim(api_version="v1", kind="PersistentVolumeClaim", metadata=meta, spec=spec)
    core.create_namespaced_persistent_volume_claim(ns, pvc)

def ensure_secret(core, ns, name, username, password):
    data = {"FB_USERNAME": username, "FB_PASSWORD": password}
    body = client.V1Secret(
        api_version="v1",
        kind="Secret",
        metadata=client.V1ObjectMeta(name=name, namespace=ns),
        type="Opaque",
        string_data=data
    )
    try:
        core.read_namespaced_secret(name, ns)
        core.patch_namespaced_secret(name, ns, {"stringData": data, "type": "Opaque"})
    except ApiException as e:
        if e.status == 404:
            core.create_namespaced_secret(ns, body)
        else:
            raise

def try_read_fb_secret(core, ns, name="filebrowser-credentials"):
    """Retorna (user, password) do Secret se existir; senão, None."""
    try:
        sec = core.read_namespaced_secret(name, ns)
    except ApiException as e:
        if e.status == 404:
            return None
        raise
    data = sec.data or {}
    def b64get(key):
        v = data.get(key)
        if not v:
            return None
        try:
            return base64.b64decode(v).decode("utf-8")
        except Exception:
            return None
    user = b64get("FB_USERNAME")
    pwd = b64get("FB_PASSWORD")
    if user or pwd:
        return (user or "admin", pwd or "")
    return None

def list_rwx_pvcs(core, ns):
    pvcs = core.list_namespaced_persistent_volume_claim(ns).items
    out = []
    for p in pvcs:
        am = (p.spec.access_modes or [])
        phase = (p.status.phase or "")
        if "ReadWriteMany" in am and phase.lower() == "bound":
            out.append(p.metadata.name)
    return sorted(set(out))

def list_namespaces(core):
    """Retorna lista ordenada de namespaces (requer RBAC de list)."""
    nss = core.list_namespace().items
    return sorted([n.metadata.name for n in nss])

def ensure_service(core, ns, name, selector_label):
    svc_spec = client.V1ServiceSpec(
        selector={APP_LABEL_KEY: selector_label},
        ports=[client.V1ServicePort(name="http", port=8080, target_port="http")],
        type="ClusterIP"
    )
    body = client.V1Service(
        api_version="v1",
        kind="Service",
        metadata=client.V1ObjectMeta(name=name, namespace=ns, labels={APP_LABEL_KEY: selector_label}),
        spec=svc_spec
    )
    try:
        core.read_namespaced_service(name, ns)
        core.patch_namespaced_service(name, ns, {
            "metadata": {"labels": {APP_LABEL_KEY: selector_label}},
            "spec": {
                "selector": {APP_LABEL_KEY: selector_label},
                "ports": [{"name": "http", "port": 8080, "targetPort": "http"}],
            },
        })
    except ApiException as e:
        if e.status == 404:
            core.create_namespaced_service(ns, body)
        else:
            raise

def route_api_available():
    try:
        apis = client.ApisApi().get_api_versions()
        groups = [g.name for g in apis.groups or []]
        return any("route.openshift.io" in g for g in groups)
    except Exception:
        return False

def ensure_route(ns, name, svc, host=None):
    co = client.CustomObjectsApi()
    group, version, plural = "route.openshift.io", "v1", "routes"
    spec = {
        "to": {"kind": "Service", "name": svc, "weight": 100},
        "port": {"targetPort": "http"},
        "tls": {"termination": "edge", "insecureEdgeTerminationPolicy": "Redirect"},
    }
    if host:
        spec["host"] = host
    body = {
        "apiVersion": f"{group}/{version}",
        "kind": "Route",
        "metadata": {"name": name, "namespace": ns, "labels": {APP_LABEL_KEY: DEPLOY_NAME}},
        "spec": spec
    }
    try:
        co.get_namespaced_custom_object(group, version, ns, plural, name)
        co.patch_namespaced_custom_object(group, version, ns, plural, name, {"spec": spec, "metadata": {"labels": {APP_LABEL_KEY: DEPLOY_NAME}}})
    except ApiException as e:
        if e.status == 404:
            co.create_namespaced_custom_object(group, version, ns, plural, body)
        else:
            raise

def build_deployment(ns, selected_pvcs, fb_user_secret):
    volumes = [
        client.V1Volume(name="cfg-db", persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(claim_name=PVC_DB_NAME)),
        client.V1Volume(name="cfg-settings", persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(claim_name=PVC_CFG_NAME)),
        client.V1Volume(name="tmp", empty_dir=client.V1EmptyDirVolumeSource()),
        client.V1Volume(name="init-data-root", empty_dir=client.V1EmptyDirVolumeSource()),
    ]
    mounts = [
        client.V1VolumeMount(name="cfg-db", mount_path="/database"),
        client.V1VolumeMount(name="cfg-settings", mount_path="/config"),
        client.V1VolumeMount(name="tmp", mount_path="/tmp"),
    ]
    for pvc in selected_pvcs:
        import hashlib
        base = f"pvc-{pvc}".replace("_", "-")
        h = hashlib.md5(pvc.encode("utf-8")).hexdigest()[:8]
        vname = (base[:52] + "-" + h) if len(base) > 53 else (base + "-" + h)
        volumes.append(client.V1Volume(name=vname,
                        persistent_volume_claim=client.V1PersistentVolumeClaimVolumeSource(claim_name=pvc)))
        mounts.append(client.V1VolumeMount(name=vname, mount_path=f"/data/{pvc}"))
    init_cmd = r"""
set -euo pipefail
echo ">> verificando /database e /config"
test -d /database && test -d /config

FB_BIN="$(command -v filebrowser || true)"
[ -n "$FB_BIN" ] || { echo "ERRO: filebrowser não encontrado"; exit 1; }

DB="/database/filebrowser.db"
if [ ! -f "$DB" ]; then
  echo ">> criando DB"
  "$FB_BIN" -d "$DB" config init
fi

"$FB_BIN" -d "$DB" config set --root /data || true
"$FB_BIN" -d "$DB" config set --port 8080 || true

try() { n=0; until "$@"; do n=$((n+1)); [ $n -ge 5 ] && return 1; echo "retry $n..."; sleep 1; done; }

USER="${FB_USERNAME:-admin}"
PASS="${FB_PASSWORD:-admin}"
echo ">> garantindo admin $USER"
if ! try "$FB_BIN" -d "$DB" users add "$USER" "$PASS" --perm.admin=true; then
  try "$FB_BIN" -d "$DB" users update "$USER" -p "$PASS"
fi

echo ">> usuários atuais:"
"$FB_BIN" -d "$DB" users ls || true
"""
    init = client.V1Container(
        name="init-filebrowser-db",
        image=FILEBROWSER_IMAGE,
        image_pull_policy="IfNotPresent",
        command=["sh", "-lc", init_cmd],
        env_from=[client.V1EnvFromSource(secret_ref=client.V1SecretEnvSource(name=fb_user_secret))],
        security_context=client.V1SecurityContext(allow_privilege_escalation=False, capabilities=client.V1Capabilities(drop=["ALL"])),
        volume_mounts=[
            client.V1VolumeMount(name="cfg-db", mount_path="/database"),
            client.V1VolumeMount(name="cfg-settings", mount_path="/config"),
            client.V1VolumeMount(name="init-data-root", mount_path="/data"),
        ],
    )
    # Probes de saúde
    http_get = client.V1HTTPGetAction(path="/", port="http")
    readiness = client.V1Probe(http_get=http_get, initial_delay_seconds=5, period_seconds=10)
    liveness = client.V1Probe(http_get=http_get, initial_delay_seconds=15, period_seconds=20)

    container = client.V1Container(
        name="filebrowser",
        image=FILEBROWSER_IMAGE,
        image_pull_policy="IfNotPresent",
        args=["-d", "/database/filebrowser.db", "-r", "/data", "-p", "8080"],
        ports=[client.V1ContainerPort(container_port=8080, name="http")],
        env_from=[client.V1EnvFromSource(secret_ref=client.V1SecretEnvSource(name=fb_user_secret))],
        security_context=client.V1SecurityContext(
            allow_privilege_escalation=False,
            read_only_root_filesystem=True,
            capabilities=client.V1Capabilities(drop=["ALL"])
        ),
        volume_mounts=mounts,
        readiness_probe=readiness,
        liveness_probe=liveness,
        resources=client.V1ResourceRequirements(
            requests={"cpu": "50m", "memory": "128Mi"},
            limits={"cpu": "500m", "memory": "512Mi"},
        ),
    )
    pod_sec = client.V1PodSecurityContext(
        run_as_non_root=True,
        seccomp_profile=client.V1SeccompProfile(type="RuntimeDefault")
    )
    pod = client.V1PodSpec(
        security_context=pod_sec,
        init_containers=[init],
        containers=[container],
        volumes=volumes,
    )
    tmpl = client.V1PodTemplateSpec(
        metadata=client.V1ObjectMeta(labels={APP_LABEL_KEY: DEPLOY_NAME}),
        spec=pod
    )
    spec = client.V1DeploymentSpec(
        replicas=1,
        selector=client.V1LabelSelector(match_labels={APP_LABEL_KEY: DEPLOY_NAME}),
        template=tmpl
    )
    dep = client.V1Deployment(
        api_version="apps/v1",
        kind="Deployment",
        metadata=client.V1ObjectMeta(name=DEPLOY_NAME, namespace=ns, labels={APP_LABEL_KEY: DEPLOY_NAME}),
        spec=spec
    )
    return dep

def apply_deployment(apps, ns, dep):
    try:
        apps.read_namespaced_deployment(dep.metadata.name, ns)
        spec_dict = dep.spec.to_dict() if hasattr(dep.spec, 'to_dict') else dep.spec
        patch = {"spec": spec_dict, "metadata": {"labels": dep.metadata.labels}}
        apps.patch_namespaced_deployment(dep.metadata.name, ns, patch)
        return "updated"
    except ApiException as e:
        if e.status == 404:
            apps.create_namespaced_deployment(ns, dep)
            return "created"
        else:
            raise

def delete_if_exists(func_get, func_del, *ids):
    """Helper genérico: deleta se existir."""
    try:
        func_get(*ids)
    except ApiException as e:
        if e.status == 404:
            return False
        raise
    func_del(*ids)
    return True

def cleanup_filebrowser(core, apps, ns):
    """Remove Deployment, Service, Route (se houver), Secret e PVCs internos."""
    try:
        delete_if_exists(apps.read_namespaced_deployment, apps.delete_namespaced_deployment, DEPLOY_NAME, ns)
    except Exception:
        pass
    try:
        delete_if_exists(core.read_namespaced_service, core.delete_namespaced_service, SERVICE_NAME, ns)
    except Exception:
        pass
    try:
        delete_if_exists(core.read_namespaced_secret, core.delete_namespaced_secret, SECRET_NAME, ns)
    except Exception:
        pass
    try:
        delete_if_exists(core.read_namespaced_persistent_volume_claim, core.delete_namespaced_persistent_volume_claim, PVC_DB_NAME, ns)
    except Exception:
        pass
    try:
        delete_if_exists(core.read_namespaced_persistent_volume_claim, core.delete_namespaced_persistent_volume_claim, PVC_CFG_NAME, ns)
    except Exception:
        pass
    if route_api_available():
        try:
            co = client.CustomObjectsApi()
            co.get_namespaced_custom_object("route.openshift.io", "v1", ns, "routes", ROUTE_NAME)
            co.delete_namespaced_custom_object("route.openshift.io", "v1", ns, "routes", ROUTE_NAME)
        except ApiException:
            pass

# ----------------- Autocomplete (Entry com popup) -----------------
class AutocompleteEntry:
    """Autocomplete para namespaces: Entry + Listbox popup filtrando por prefixo/substr."""
    def __init__(self, parent, on_select_callback):
        self.parent = parent
        self.on_select_callback = on_select_callback
        self.var = ctk.StringVar(value="")
        self.entry = (ctk.CTkEntry(parent, textvariable=self.var)
                      if GUI_LIB == "ctk" else ctk.Entry(parent, textvariable=self.var, width=40))
        self.popup = None
        self.values = []
        self.entry.bind("<KeyRelease>", self._on_keyrelease)
        self.entry.bind("<Down>", self._on_down)
        self.entry.bind("<Up>", self._on_up)
        self.entry.bind("<Return>", self._on_return)
        self.entry.bind("<Escape>", self._hide_popup)

    def widget(self):
        return self.entry

    def set_values(self, values):
        self.values = list(values or [])

    def get(self):
        return self.var.get()

    def set(self, text):
        self.var.set(text)

    def _filtered(self, text):
        t = text.strip().lower()
        if not t:
            return self.values[:30]
        starts = [v for v in self.values if v.lower().startswith(t)]
        if len(starts) < 30:
            contains = [v for v in self.values if t in v.lower() and not v.lower().startswith(t)]
            return (starts + contains)[:30]
        return starts[:30]

    def _show_popup(self, items):
        if self.popup:
            try:
                self.popup.destroy()
            except Exception:
                pass
        if not items:
            return
        self.popup = ctk.CTkToplevel(self.parent) if GUI_LIB == "ctk" else ctk.Toplevel(self.parent)
        self.popup.wm_overrideredirect(True)
        self.popup.attributes("-topmost", True)
        try:
            x = self.entry.winfo_rootx()
            y = self.entry.winfo_rooty() + self.entry.winfo_height()
            w = max(self.entry.winfo_width(), 280)
            self.popup.geometry(f"{w}x220+{x}+{y}")
        except Exception:
            pass
        if GUI_LIB == "ctk":
            import tkinter as tk
            frame = ctk.CTkFrame(self.popup); frame.pack(fill="both", expand=True)
            lb = tk.Listbox(frame, activestyle="dotbox"); lb.pack(fill="both", expand=True)
        else:
            import tkinter as tk
            lb = tk.Listbox(self.popup, activestyle="dotbox"); lb.pack(fill="both", expand=True)
        for it in items:
            lb.insert("end", it)
        lb.bind("<ButtonRelease-1>", lambda e: self._choose(lb))
        lb.bind("<Return>", lambda e: self._choose(lb))
        lb.bind("<Escape>", lambda e: self._hide_popup())
        self._lb = lb

    def _hide_popup(self, *args):
        if self.popup:
            try:
                self.popup.destroy()
            except Exception:
                pass
            self.popup = None

    def _choose(self, lb):
        try:
            sel = lb.get(lb.curselection())
        except Exception:
            self._hide_popup(); return
        self.set(sel)
        self._hide_popup()
        if callable(self.on_select_callback):
            self.on_select_callback(sel)

    def _on_keyrelease(self, event=None):
        text = self.get()
        items = self._filtered(text)
        self._show_popup(items)

    def _on_down(self, event=None):
        if not self.popup: return "break"
        try:
            if self._lb.size() > 0:
                self._lb.selection_clear(0, "end")
                self._lb.selection_set(0)
                self._lb.activate(0)
                self._lb.focus_set()
        except Exception:
            pass
        return "break"

    def _on_up(self, event=None):
        return "break"

    def _on_return(self, event=None):
        if self.popup and getattr(self, "_lb", None):
            self._choose(self._lb)
            return "break"
        if callable(self.on_select_callback):
            self.on_select_callback(self.get())

# ----------------- UI App -----------------
class FBGuiApp:
    def __init__(self):
        if GUI_LIB == "ctk":
            ctk.set_appearance_mode("system")
            ctk.set_default_color_theme("blue")
            self.root = ctk.CTk()
            self.root.title("Filebrowser RWX Mount - OpenShift")
        else:
            self.root = ctk.Tk()
            self.root.title("Filebrowser RWX Mount - OpenShift")

        # Janela com tamanho fixo
        try:
            self.root.geometry("1020x700")
            self.root.resizable(False, False)
        except Exception:
            pass

        # ícones (se existirem no diretório)
        try:
            import tkinter as tk
            if os.path.exists("icon.ico"):
                try: self.root.iconbitmap("icon.ico")
                except Exception: pass
            if os.path.exists("icon.png"):
                try: self.root.iconphoto(True, tk.PhotoImage(file="icon.png"))
                except Exception: pass
        except Exception:
            pass

        self.log_q = queue.Queue()
        self.kcfg_tmpdir = None
        self.env = None
        self.core = None
        self.apps = None
        self.insecure_flag = False
        self.ns_values = []
        self.pending_generated_pwd = ""

        self._build_login_frame()
        self._build_ns_frame()
        self._build_pvc_frame()
        self._build_actions_frame()
        self._build_log_frame()
        self._build_footer()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self._toggle_post_login(enabled=False)
        self._poll_log()

    # ---------- UI builders ----------
    def _build_login_frame(self):
        frm = ctk.CTkFrame(self.root) if GUI_LIB == "ctk" else ctk.Frame(self.root, padx=8, pady=8)
        frm.pack(fill="x", padx=8, pady=6)

        lbl_api = "API Server"
        if GUI_LIB == "ctk":
            ctk.CTkLabel(frm, text=lbl_api).grid(row=0, column=0, sticky="w")
            self.api_entry = ctk.CTkEntry(frm)
        else:
            ctk.Label(frm, text=lbl_api).grid(row=0, column=0, sticky="w")
            self.api_entry = ctk.Entry(frm, width=45)

        self.api_entry.insert(0, DEFAULT_API_SERVER)

        if GUI_LIB == "ctk":
            ctk.CTkLabel(frm, text="Usuário (cluster)").grid(row=0, column=1, padx=8, sticky="w")
            self.user_entry = ctk.CTkEntry(frm, width=180)
            self.pwd_entry = ctk.CTkEntry(frm, show="*", width=180)
            ctk.CTkLabel(frm, text="Senha").grid(row=0, column=2, sticky="w", padx=(8,0))
            self.user_entry.grid(row=1, column=1, padx=8, sticky="we")
            self.pwd_entry.grid(row=1, column=2, padx=8, sticky="we")
            self.insecure_var = ctk.BooleanVar(value=False)
            self.insecure_chk = ctk.CTkCheckBox(frm, text="Ignorar TLS interno", variable=self.insecure_var)
            self.insecure_chk.grid(row=1, column=3, padx=8)
            self.login_btn = ctk.CTkButton(frm, text="Login (oc)", command=self._on_login)
            self.login_btn.grid(row=1, column=4, padx=8)
        else:
            ctk.Label(frm, text="Usuário (cluster)").grid(row=0, column=1, sticky="w", padx=8)
            self.user_entry = ctk.Entry(frm, width=20); self.user_entry.grid(row=1, column=1, padx=8, sticky="we")
            ctk.Label(frm, text="Senha").grid(row=0, column=2, sticky="w", padx=8)
            self.pwd_entry = ctk.Entry(frm, show="*", width=20); self.pwd_entry.grid(row=1, column=2, padx=8, sticky="we")
            self.insecure_var = ctk.BooleanVar(value=False)
            self.insecure_chk = ctk.Checkbutton(frm, text="Ignorar TLS interno", variable=self.insecure_var)
            self.insecure_chk.grid(row=1, column=3, padx=8)
            self.login_btn = ctk.Button(frm, text="Login (oc)", command=self._on_login)
            self.login_btn.grid(row=1, column=4, padx=8)

        self.api_entry.grid(row=1, column=0, sticky="we")
        if GUI_LIB == "ctk":
            frm.grid_columnconfigure(0, weight=1)

    def _build_ns_frame(self):
        frm = ctk.CTkFrame(self.root) if GUI_LIB == "ctk" else ctk.Frame(self.root, padx=8, pady=8)
        frm.pack(fill="x", padx=8, pady=6)

        if GUI_LIB == "ctk":
            ctk.CTkLabel(frm, text="Namespace alvo").grid(row=0, column=0, sticky="w")
        else:
            ctk.Label(frm, text="Namespace alvo").grid(row=0, column=0, sticky="w")

        self.ns_aut = AutocompleteEntry(frm, on_select_callback=self._on_ns_pick_text)
        self.ns_entry = self.ns_aut.widget()
        self.ns_entry.grid(row=0, column=1, sticky="we", padx=8)

        if GUI_LIB == "ctk":
            self.refresh_ns_btn = ctk.CTkButton(frm, text="Atualizar Namespaces", command=self._on_refresh_ns)
            self.scan_btn = ctk.CTkButton(frm, text="Atualizar PVCs", command=self._on_scan)
        else:
            self.refresh_ns_btn = ctk.Button(frm, text="Atualizar Namespaces", command=self._on_refresh_ns)
            self.scan_btn = ctk.Button(frm, text="Atualizar PVCs", command=self._on_scan)

        self.refresh_ns_btn.grid(row=0, column=2, padx=8)
        self.scan_btn.grid(row=0, column=3, padx=8)

        if GUI_LIB == "ctk":
            frm.grid_columnconfigure(1, weight=1)

    def _build_pvc_frame(self):
        title = "PVCs RWX (marque para montar)"
        frm = ctk.CTkFrame(self.root) if GUI_LIB == "ctk" else ctk.LabelFrame(self.root, text=title, padx=8, pady=8)
        frm.pack(fill="both", expand=True, padx=8, pady=6)
        self.pvc_container = frm
        self.pvc_checks = {}

    def _build_actions_frame(self):
        frm = ctk.CTkFrame(self.root) if GUI_LIB == "ctk" else ctk.Frame(self.root, padx=8, pady=8)
        frm.pack(fill="x", padx=8, pady=6)

        if GUI_LIB == "ctk":
            ctk.CTkLabel(frm, text="FB User").grid(row=0, column=0, sticky="w")
            self.fb_user = ctk.CTkEntry(frm, width=160); self.fb_user.insert(0, "admin")
            ctk.CTkLabel(frm, text="FB Senha").grid(row=0, column=1, sticky="w", padx=(8,0))
            self.fb_pass = ctk.CTkEntry(frm, show="*", width=200)  # começa vazio
            self.copy_pwd_btn = ctk.CTkButton(frm, text="Copiar senha", width=120, command=self._on_copy_pwd)
            ctk.CTkLabel(frm, text="Route Host (opcional)").grid(row=0, column=3, sticky="w", padx=(8,0))
            self.route_host = ctk.CTkEntry(frm, width=320)
            self.apply_btn = ctk.CTkButton(frm, text="Aplicar Filebrowser", command=self._on_apply)
            self.cleanup_btn = ctk.CTkButton(frm, text="Remover Filebrowser (limpeza)", fg_color="#b91c1c", hover_color="#991b1b", command=self._on_cleanup)
            self.remove_after_apply_var = ctk.BooleanVar(value=True)
            self.remove_after_apply_chk = ctk.CTkCheckBox(frm, text="Remover ao finalizar", variable=self.remove_after_apply_var)
        else:
            ctk.Label(frm, text="FB User").grid(row=0, column=0, sticky="w")
            self.fb_user = ctk.Entry(frm, width=18); self.fb_user.insert(0, "admin")
            ctk.Label(frm, text="FB Senha").grid(row=0, column=1, sticky="w", padx=(8,0))
            self.fb_pass = ctk.Entry(frm, show="*", width=20)
            self.copy_pwd_btn = ctk.Button(frm, text="Copiar senha", width=12, command=self._on_copy_pwd)
            ctk.Label(frm, text="Route Host (opcional)").grid(row=0, column=3, sticky="w", padx=8)
            self.route_host = ctk.Entry(frm, width=40)
            self.apply_btn = ctk.Button(frm, text="Aplicar/Atualizar Filebrowser", command=self._on_apply)
            self.cleanup_btn = ctk.Button(frm, text="Remover Filebrowser (limpeza)", command=self._on_cleanup)
            self.remove_after_apply_var = ctk.BooleanVar(value=True)
            self.remove_after_apply_chk = ctk.Checkbutton(frm, text="Remover ao finalizar", variable=self.remove_after_apply_var)

        self.fb_user.grid(row=1, column=0, sticky="w")
        self.fb_pass.grid(row=1, column=1, sticky="w", padx=(8,0))
        self.copy_pwd_btn.grid(row=1, column=2, padx=(8,0))
        self.route_host.grid(row=1, column=3, sticky="we", padx=(8,0))
        self.apply_btn.grid(row=1, column=4, padx=8)
        self.cleanup_btn.grid(row=1, column=5, padx=8)
        self.remove_after_apply_chk.grid(row=1, column=6, padx=8)

        if GUI_LIB == "ctk":
            frm.grid_columnconfigure(3, weight=1)

    def _build_log_frame(self):
        frm = ctk.CTkFrame(self.root) if GUI_LIB == "ctk" else ctk.Frame(self.root, padx=8, pady=8)
        frm.pack(fill="both", expand=True, padx=8, pady=6)
        if GUI_LIB == "ctk":
            self.log_txt = ctk.CTkTextbox(frm, height=180)
            self.log_txt.pack(fill="both", expand=True)
        else:
            self.log_txt = ctk.Text(frm, height=14)
            self.log_txt.pack(fill="both", expand=True)

    def _build_footer(self):
        if GUI_LIB == "ctk":
            frm = ctk.CTkFrame(self.root, height=22)
            frm.pack(side="bottom", fill="x")
            lbl = ctk.CTkLabel(frm, text=f"Versão {VERSAO}")
            lbl.pack(side="right", padx=8, pady=2)
        else:
            frm = ctk.Frame(self.root)
            frm.pack(side="bottom", fill="x")
            lbl = ctk.Label(frm, text=f"Versão {VERSAO}")
            lbl.pack(side="right", padx=8, pady=2)

    def _toggle_post_login(self, enabled: bool):
        state = ("normal" if enabled else "disabled")
        try:
            self.ns_entry.configure(state=state)
            self.scan_btn.configure(state=state)
            self.refresh_ns_btn.configure(state=state)
            self.fb_user.configure(state=state)
            self.fb_pass.configure(state=state)
            self.copy_pwd_btn.configure(state=state)
            self.route_host.configure(state=state)
            self.apply_btn.configure(state=state)
            self.cleanup_btn.configure(state=state)
            self.remove_after_apply_chk.configure(state=state)
        except Exception:
            pass

    def _clear_pvc_checks(self):
        for w in list(self.pvc_container.children.values()):
            try:
                w.destroy()
            except Exception:
                pass
        self.pvc_checks.clear()

    def _add_log(self, msg: str):
        self.log_q.put(msg)

    def _poll_log(self):
        try:
            while True:
                msg = self.log_q.get_nowait()
                self.log_txt.insert("end", msg + "\n")
                self.log_txt.see("end")
        except queue.Empty:
            pass
        self.root.after(120, self._poll_log)

    # ---------- Actions ----------
    def _on_copy_pwd(self):
        try:
            pwd = self.fb_pass.get().strip()
            if not pwd:
                self._add_log("Nada para copiar: senha vazia.")
                return
            self.root.clipboard_clear()
            self.root.clipboard_append(pwd)
            self._add_log("Senha copiada para a área de transferência.")
        except Exception as e:
            self._add_log(f"Falha ao copiar senha: {e}")

    def _on_login(self):
        server = self.api_entry.get().strip() or DEFAULT_API_SERVER
        user = self.user_entry.get().strip()
        pwd = self.pwd_entry.get().strip()
        insecure = bool(self.insecure_var.get())
        self.insecure_flag = insecure

        def work():
            self._add_log(f">> Fazendo oc login em {server} com usuário {user} ...")
            try:
                self.kcfg_tmpdir = tempfile.TemporaryDirectory()
                kcfg = os.path.join(self.kcfg_tmpdir.name, "kubeconfig")
                _, env = oc_login(server, user, pwd, kcfg, insecure=insecure)
                self.env = env
                load_kube_from(env, insecure=insecure)
                self.core = client.CoreV1Api()
                self.apps = client.AppsV1Api()
                self._add_log("OK: login efetuado.")
                try:
                    self.root.after(0, lambda: self._toggle_post_login(True))
                except Exception:
                    pass
                # Atualiza namespaces automaticamente após login
                try:
                    self.root.after(0, self._on_refresh_ns)
                    # Após atualizar namespaces, se já houver NS preenchido, atualiza PVCs
                    self.root.after(1200, lambda: (self._on_scan() if (self.ns_aut.get() or "").strip() else None))
                except Exception:
                    pass
            except Exception as e:
                self._add_log(f"ERRO login: {e}")
            finally:
                try:
                    self.root.after(0, lambda: self.login_btn.configure(state="normal"))
                except Exception:
                    pass
        try:
            self.login_btn.configure(state="disabled")
        except Exception:
            pass
        threading.Thread(target=work, daemon=True).start()

    def _on_refresh_ns(self):
        """Carrega a lista de namespaces do cluster e injeta no autocompletar."""
        def work():
            self._add_log(">> Buscando namespaces...")
            try:
                nss = list_namespaces(self.core)
                self.ns_values = nss
                try:
                    self.root.after(0, lambda: self.ns_aut.set_values(nss))
                except Exception:
                    pass
                self._add_log("Namespaces carregados.")  # solicitado: não listar todos
            except Exception as e:
                self._add_log(f"ERRO ao listar namespaces: {e}")
        threading.Thread(target=work, daemon=True).start()

    def _on_ns_pick_text(self, value: str):
        ns = (value or "").strip()
        if ns:
            try:
                suggested = f"filebrowser-{ns}.{ROUTE_DOMAIN}"
                if not self.route_host.get().strip():
                    self.root.after(0, lambda s=suggested: (self.route_host.delete(0, "end"), self.route_host.insert(0, s)))
            except Exception:
                pass
            try:
                self.root.after(0, self._on_scan)
            except Exception:
                pass

    def _on_scan(self):
        ns = self.ns_aut.get().strip()
        if not ns:
            self._add_log("Informe o namespace.")
            return

        def work():
            self._add_log(f">> Namespace alvo: {ns}")
            self._clear_pvc_checks()
            self.pending_generated_pwd = ""

            try:
                ensure_namespace_exists(self.core, ns)
            except Exception as e:
                self._add_log(f"ERRO namespace: {e}")
                return

            try:
                if not (self.route_host.get().strip()):
                    suggested = f"filebrowser-{ns}.{ROUTE_DOMAIN}"
                    try:
                        self.route_host.delete(0, "end")
                        self.route_host.insert(0, suggested)
                    except Exception:
                        pass

                # Credenciais
                try:
                    creds = try_read_fb_secret(self.core, ns, SECRET_NAME)
                    if creds:
                        u, p = creds
                        try:
                            self.root.after(0, lambda u=u: (self.fb_user.delete(0, "end"), self.fb_user.insert(0, u or "admin")))
                            self.root.after(0, lambda p=p: (self.fb_pass.delete(0, "end"), self.fb_pass.insert(0, p or "")))
                            self._add_log("Secret existente detectado: credenciais carregadas da API.")
                        except Exception:
                            pass
                    else:
                        newpwd = gen_password(12)
                        self.pending_generated_pwd = newpwd
                        try:
                            self.root.after(0, lambda s=newpwd: (self.fb_pass.delete(0, "end"), self.fb_pass.insert(0, s)))
                        except Exception:
                            pass
                        self._add_log("Secret não encontrado: senha gerada automaticamente (12+ chars, maiús/minús).")
                except Exception as e:
                    self._add_log(f"Aviso: não foi possível ler o Secret existente: {e}")

                # PVCs
                pvcs = list_rwx_pvcs(self.core, ns)
                pvcs = [p for p in pvcs if p not in (PVC_DB_NAME, PVC_CFG_NAME)]
                if not pvcs:
                    self._add_log("Nenhum PVC RWX (Bound) encontrado.")
                    return
                self._add_log(f"Encontrados: {', '.join(pvcs)}")
                r = 0
                for pvc in pvcs:
                    try:
                        def _add_chk(p=pvc, row=r):
                            var = ctk.BooleanVar(value=True)
                            if GUI_LIB == "ctk":
                                chk = ctk.CTkCheckBox(self.pvc_container, text=p, variable=var)
                                chk.grid(row=row, column=0, sticky="w", padx=8, pady=2)
                            else:
                                chk = ctk.Checkbutton(self.pvc_container, text=p, variable=var)
                                chk.grid(row=row, column=0, sticky="w", padx=8, pady=2)
                            self.pvc_checks[p] = var
                        self.root.after(0, _add_chk)
                    except Exception:
                        pass
                    r += 1
            except Exception as e:
                self._add_log(f"ERRO scan: {e}")

        threading.Thread(target=work, daemon=True).start()

    def _on_apply(self):
        ns = self.ns_aut.get().strip()
        fb_user = self.fb_user.get().strip() or "admin"
        route_host = self.route_host.get().strip() or None
        remove_after = bool(self.remove_after_apply_var.get())

        selected = [p for p, v in self.pvc_checks.items() if bool(v.get())]
        if not ns:
            self._add_log("Informe o namespace.")
            return

        def work():
            self._add_log(">> Aplicando recursos do Filebrowser...")
            try:
                ensure_pvc(self.core, ns, PVC_DB_NAME, "1Gi", STORAGECLASS_CEPHFS, ["ReadWriteMany"])
                ensure_pvc(self.core, ns, PVC_CFG_NAME, "100Mi", STORAGECLASS_CEPHFS, ["ReadWriteMany"])
                self._add_log("PVCs internos OK.")

                # Decide senha
                existing = try_read_fb_secret(self.core, ns, SECRET_NAME)
                if existing:
                    fb_user_use, fb_pass_use = existing[0] or fb_user, existing[1] or ""
                    try:
                        self.root.after(0, lambda u=fb_user_use: (self.fb_user.delete(0, "end"), self.fb_user.insert(0, u or "admin")))
                        self.root.after(0, lambda p=fb_pass_use: (self.fb_pass.delete(0, "end"), self.fb_pass.insert(0, p)))
                    except Exception:
                        pass
                    self._add_log("Secret existente: reutilizando senha cadastrada.")
                else:
                    fb_user_use = fb_user or "admin"
                    fb_pass_use = self.fb_pass.get().strip() or self.pending_generated_pwd or gen_password(12)
                    try:
                        self.root.after(0, lambda s=fb_pass_use: (self.fb_pass.delete(0, "end"), self.fb_pass.insert(0, s)))
                    except Exception:
                        pass
                    self._add_log("Secret não encontrado: definindo senha automática (12+ chars, maiús/minús).")

                ensure_secret(self.core, ns, SECRET_NAME, fb_user_use, fb_pass_use)
                self._add_log("Secret OK.")

                dep = build_deployment(ns, selected, SECRET_NAME)
                result = apply_deployment(self.apps, ns, dep)
                self._add_log(f"Deployment {result}.")

                ensure_service(self.core, ns, SERVICE_NAME, DEPLOY_NAME)
                self._add_log("Service OK.")

                if route_api_available():
                    ensure_route(ns, ROUTE_NAME, SERVICE_NAME, host=route_host)
                    if route_host:
                        self._add_log(f"Route OK. Host: https://{route_host}")
                    else:
                        self._add_log("Route OK (host será gerado pelo OpenShift).")
                else:
                    self._add_log("Cluster sem API de Route. Use 'oc port-forward'.")

                self._add_log("Concluído. Aguarde rollout e acesse via Route/Service.")
                if remove_after:
                    self._add_log(">> Remover ao finalizar está habilitado. Ao fechar a janela, farei a limpeza.")
            except Exception as e:
                self._add_log(f"ERRO aplicar: {e}")

        threading.Thread(target=work, daemon=True).start()

    def _on_cleanup(self):
        ns = self.ns_aut.get().strip()
        if not ns:
            self._add_log("Informe o namespace para limpar.")
            return

        def work():
            self._add_log(">> Removendo Filebrowser e artefatos internos...")
            try:
                cleanup_filebrowser(self.core, self.apps, ns)
                self._add_log("Limpeza concluída: Deployment, Service, Route, Secret e PVCs internos foram removidos.")
            except Exception as e:
                self._add_log(f"ERRO limpeza: {e}")

        threading.Thread(target=work, daemon=True).start()

    def _on_close(self):
        """Se 'Remover ao finalizar' estiver marcado, limpa antes de sair."""
        remove_after = bool(self.remove_after_apply_var.get())
        ns = (self.ns_aut.get().strip() if hasattr(self, "ns_aut") else "")
        if remove_after and self.core and self.apps and ns:
            dlg = None; prog = None
            try:
                if GUI_LIB == "ctk":
                    dlg = ctk.CTkToplevel(self.root)
                    dlg.title("Removendo antes de sair...")
                    dlg.geometry("420x120")
                    ctk.CTkLabel(dlg, text=f"Removendo recursos do Filebrowser no namespace '{ns}'...").pack(padx=16, pady=(18, 8))
                    prog = ctk.CTkProgressBar(dlg); prog.pack(fill="x", padx=16, pady=8)
                    prog.configure(mode="indeterminate"); prog.start()
                else:
                    dlg = ctk.Toplevel(self.root)
                    dlg.title("Removendo antes de sair...")
                    ctk.Label(dlg, text=f"Removendo recursos do Filebrowser no namespace '{ns}'...").pack(padx=16, pady=(18, 8))
                    try:
                        from tkinter import ttk
                        prog = ttk.Progressbar(dlg, mode="indeterminate"); prog.pack(fill="x", padx=16, pady=8); prog.start(10)
                    except Exception:
                        pass
                dlg.transient(self.root); dlg.grab_set(); dlg.update()
            except Exception:
                dlg = None

            done_flag = {"done": False}
            def cleanup_and_exit():
                try:
                    cleanup_filebrowser(self.core, self.apps, ns)
                except Exception:
                    pass
                done_flag["done"] = True

            t = threading.Thread(target=cleanup_and_exit, daemon=True); t.start()

            def poll_finish():
                if done_flag["done"]:
                    try:
                        if prog and GUI_LIB == "ctk": prog.stop()
                    except Exception:
                        pass
                    try:
                        if dlg: dlg.destroy()
                    except Exception:
                        pass
                    try:
                        self.root.destroy()
                    except Exception:
                        os._exit(0)
                else:
                    self.root.after(120, poll_finish)

            self._add_log("Removendo Filebrowser antes de sair...")
            poll_finish()
        else:
            try:
                self.root.destroy()
            except Exception:
                os._exit(0)

    def run(self):
        self.root.mainloop()

# ----------------- Main -----------------
if __name__ == "__main__":
    app = FBGuiApp()
    app.run()
