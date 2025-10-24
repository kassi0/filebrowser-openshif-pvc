**FB Mount RWX GUI**

- Pequena GUI para montar PVCs RWX (CephFS) em um Filebrowser dentro de um namespace no OpenShift, criando/atualizando automaticamente Secret, PVCs internos, Deployment, Service e Route.
- Requer acesso ao cluster OpenShift e o cliente `oc` disponível no PATH (ou no mesmo diretório da aplicação). Em ambientes onde o `oc` não puder ser usado, há fallback por OAuth, mas recomenda-se ter o `oc` instalado.

**Principais Funções**
- Login no cluster OpenShift (via `oc login` ou OAuth fallback).
- Listagem de namespaces e autocompletar de texto.
- Scan de PVCs com acesso `ReadWriteMany` já Bound no namespace alvo.
- Criação/atualização de recursos:
  - Secret com credenciais do Filebrowser.
  - PVCs internos do Filebrowser (`/database` e `/config`).
  - Deployment do Filebrowser apontando para os PVCs selecionados.
  - Service (porta 8080) e Route (quando a API de Route estiver disponível).
- Limpeza dos recursos criados (Deployment, Service, Route, Secret, PVCs internos).
- Opção “Remover ao finalizar” para limpar automaticamente ao fechar a janela.

**Pré‑requisitos**
- OpenShift CLI `oc` instalado e disponível no PATH, ou no mesmo diretório do executável/script.
- Python 3.10+ (para executar a partir do código-fonte ou para gerar binários com PyInstaller).
- Pacotes Python (ver `requirements.txt`).

**Baixar o oc CLI**
- Página oficial (última versão):
  - https://mirror.openshift.com/pub/openshift-v4/clients/ocp/latest/
- Documentação: https://docs.openshift.com/container-platform/latest/cli_reference/openshift_cli/getting-started-cli.html
- macOS via Homebrew (alternativa): `brew install openshift-client` (ou `brew install openshift-cli` em algumas distros de fórmulas).
- RHEL/Fedora: `sudo dnf install openshift-clients`.
- Qualquer SO: baixar o tar/zip do link acima, extrair e colocar o binário `oc` no PATH.

**Como usar no Windows**
- Executar diretamente o binário: `dist/fb_mount_rwx_gui.exe` (ou construir conforme seção “Gerar executável”).
- Certifique-se de que `oc.exe` esteja no PATH ou no mesmo diretório do `.exe`.
- Passos no app:
  - Informe o API Server, usuário e senha; marque “Ignorar TLS interno” se necessário; clique em Login.
  - Clique em “Atualizar Namespaces”, selecione/complete o namespace.
  - Clique em “Atualizar PVCs”, marque os PVCs RWX que deseja montar.
  - Informe usuário/senha do Filebrowser (ou deixe em branco para auto-gerar).
  - Opcional: informe o host da Route.
  - Clique em “Aplicar Filebrowser”. Aguarde o rollout e acesse via Route/Service.
  - Para remover, clique em “Remover Filebrowser (limpeza)” ou habilite “Remover ao finalizar”.

**Como usar no Linux**
- Instale o `oc` e Python 3.10+. Crie um ambiente virtual e dependências:
  - `python3 -m venv .venv && source .venv/bin/activate`
  - `pip install -r requirements.txt`
  - `python fb_mount_rwx_gui.py`
- Alternativamente, gere um binário com PyInstaller (ver seção “Gerar executável”).

**Como usar no macOS**
- Instale o `oc` (ex.: `brew install openshift-client`) e Python 3.10+ (ex.: `brew install python@3.11`).
- Crie um ambiente virtual e instale dependências:
  - `python3 -m venv .venv && source .venv/bin/activate`
  - `pip install -r requirements.txt`
  - `python fb_mount_rwx_gui.py`
- Para binário nativo, gere com PyInstaller no próprio macOS.

**Gerar o executável (PyInstaller)**
- Requisitos: `pip install -r requirements.txt` (inclui `pyinstaller`).
- Usando o arquivo `.spec` incluso:
  - `pyinstaller --clean --noconfirm fb_mount_rwx_gui.spec`
- Ou modo direto (exemplo simples):
  - Windows: `pyinstaller --onefile --windowed --icon icon.ico fb_mount_rwx_gui.py`
  - Linux/macOS: `pyinstaller --onefile --windowed fb_mount_rwx_gui.py`
- Após gerar, copie `oc`/`oc.exe` para o mesmo diretório do executável, ou garanta que esteja no PATH do sistema.

**Variáveis de ambiente úteis**
- `OCP_OC_PATH`: caminho absoluto para o binário `oc` (prioriza sobre PATH).
- `FILEBROWSER_IMAGE`: substitui a imagem padrão do Filebrowser (ex.: para fixar tag/digest).

**Notas de Segurança/Compatibilidade**
- O aplicativo aplica políticas de segurança no Pod (non-root, seccomp padrão) e probes HTTP.
- Em clusters com SCC restritas (OpenShift), evitar definir `runAsUser`/`fsGroup` fixos. O app não fixa `fsGroup` para compatibilidade com `restricted-v2`.
- Para CephFS RWX, garanta que os PVCs tenham permissões adequadas para escrita pelo UID/GID efetivo injetado pelo OpenShift.

**Solução de Problemas**
- “oc não encontrado”: coloque `oc`/`oc.exe` no PATH ou defina `OCP_OC_PATH` com o caminho para o binário.
- Erros de TLS: marque “Ignorar TLS interno” ao logar, se o cluster usar certificados internos/autoassinados.
- Service/Route já existem: o app faz “patch” dos recursos, preservando campos imutáveis como `clusterIP`.

**Apenas para Manutenção**
**Apenas para Manutenção**
**Apenas para Manutenção**
**Apenas para Manutenção**