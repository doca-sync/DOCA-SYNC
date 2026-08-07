# Doca <-> Mercado Livre — backend de sincronização

Esse backend faz a ponte segura entre o Doca e a API do Mercado Livre. Ele **não** fica
sincronizando sozinho — só age quando alguém aperta "Atualizar" no Doca. O motivo de ele
existir é simples: a API do Mercado Livre exige uma senha secreta (`client_secret`) pra
fazer login, e essa senha **não pode** ficar dentro do arquivo HTML do Doca (qualquer um que
abrisse o Doca no navegador conseguiria vê-la). Esse backend guarda esse segredo com
segurança, do lado de fora do navegador.

Leva uns 20-30 minutos pra deixar tudo no ar. Siga os passos na ordem.

## 1. Criar o banco de dados (Supabase — grátis)

1. Crie uma conta em https://supabase.com (dá pra entrar com GitHub).
2. Clique em "New project". Escolha um nome (ex: `doca-ml-sync`) e uma senha forte pro banco
   (guarde essa senha, vai precisar dela no passo 4).
3. Depois que o projeto for criado, vá em **SQL Editor** (menu lateral) → **New query**.
4. Cole o conteúdo do arquivo `db/schema.sql` (está nessa mesma pasta) e clique em **Run**.
   Isso cria as 3 tabelas que o backend usa.
5. Vá em **Project Settings** (ícone de engrenagem) → **Database** → **Connection string** →
   aba **URI**. Copie essa string — é o valor da variável `DATABASE_URL` que você vai usar
   no passo 4. Troque `[YOUR-PASSWORD]` na string pela senha que você definiu no passo 2.

## 2. Subir o código pro GitHub

1. Se ainda não tiver, crie uma conta em https://github.com.
2. Crie um repositório novo (pode ser privado), ex: `doca-ml-sync-backend`.
3. Suba todos os arquivos dessa pasta (`server.js`, `package.json`, `db/schema.sql`, este
   `README.md` — **não** suba um `.env` de verdade, só o `.env.example`) pra esse repositório.
   Dá pra fazer isso arrastando os arquivos direto na interface do GitHub, sem precisar usar
   linha de comando, se preferir (botão "Add file" → "Upload files").

## 3. Hospedar o backend (Render — grátis)

1. Crie uma conta em https://render.com (dá pra entrar com GitHub — mais fácil, já conecta os
   dois automaticamente).
2. Clique em **New** → **Web Service**, e selecione o repositório que você criou no passo 2.
3. Escolha um **nome** pro serviço — isso vira a URL pública dele, então escolha algo como
   `doca-ml-sync` (a URL final vai ser `https://doca-ml-sync.onrender.com`, por exemplo).
   **Anote esse nome**, vai precisar dele no próximo passo.
4. Configurações do serviço:
   - **Runtime**: Node
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Instance Type**: Free
5. Antes de clicar em criar, adicione as **variáveis de ambiente** (seção "Environment"):
   - `DATABASE_URL` → a connection string do Supabase (passo 1.5)
   - `ML_REDIRECT_URI` → `https://SEU-NOME-ESCOLHIDO.onrender.com/oauth/callback` (troque
     `SEU-NOME-ESCOLHIDO` pelo nome que você deu no passo 3.3)
   - `ML_CLIENT_ID` e `ML_CLIENT_SECRET` → deixe em branco por enquanto, você ainda não tem
     (vai voltar aqui depois do passo 4)
   - `ALLOWED_ORIGIN` → pode deixar `*` por enquanto
6. Clique em **Create Web Service**. O Render vai instalar e rodar o backend — como faltam o
   `ML_CLIENT_ID`/`ML_CLIENT_SECRET`, ele vai reiniciar sozinho até você preencher (é
   esperado, sem problema).

## 4. Criar a aplicação no Mercado Livre Developers

1. Acesse https://developers.mercadolivre.com.br, logado com a conta de vendedor da loja.
   Como você tem 4 lojas (TorvStore, Dor Block, Orbix Brasil, TorvShop) em contas
   diferentes do Mercado Livre, você vai repetir esse passo 4 uma vez **para cada loja** —
   cada uma tem sua própria aplicação e suas próprias credenciais.
2. Vá em "Minhas aplicações" → "Criar aplicação".
3. Preencha nome, descrição etc. (qualquer coisa, é só pro seu uso).
4. Em **Redirect URI**, cole exatamente: `https://SEU-NOME-ESCOLHIDO.onrender.com/oauth/callback`
   (o mesmo valor que você colocou em `ML_REDIRECT_URI` no passo 3.5).
5. Marque os escopos **read** e **offline_access** (offline_access é o que permite renovar o
   token sozinho depois, sem precisar logar de novo toda vez).
6. Depois de criar, a página mostra o **Client ID (App ID)** e o **Client Secret** — copie os
   dois.
7. Volte no Render (passo 3), edite as variáveis de ambiente e preencha `ML_CLIENT_ID` e
   `ML_CLIENT_SECRET` com esses valores. Salve — o Render vai reiniciar o serviço sozinho.

## 5. Autorizar cada loja (uma vez só)

Depois que o serviço estiver no ar (a aba "Logs" do Render mostra
`Doca ML sync backend rodando na porta ...`), abra no navegador, **logado na conta do
Mercado Livre daquela loja**:

```
https://SEU-NOME-ESCOLHIDO.onrender.com/oauth/login?loja=TorvStore
```

Troque `loja=TorvStore` pelo nome exato da loja (`TorvStore`, `Dor Block`, `Orbix Brasil` ou
`TorvShop`). Vai abrir a tela de autorização do Mercado Livre — aceite. Se dizer "Loja
autorizada com sucesso", funcionou. Repita pra cada uma das 4 lojas (cada uma com a
aplicação/credenciais criadas pra ela no passo 4).

## 6. Testar a sincronização

Pra simular o clique em "Atualizar" (isso é o que o botão do Doca vai chamar depois):

```
POST https://SEU-NOME-ESCOLHIDO.onrender.com/sync?loja=TorvStore
```

E pra ver os dados que foram salvos:

```
GET https://SEU-NOME-ESCOLHIDO.onrender.com/data?loja=TorvStore
```

Dá pra testar o `/data` direto no navegador (é um GET). Pro `/sync`, como é POST, use algo
como Postman, Insomnia, ou peça pra eu testar por aqui mesmo.

## O que falta depois disso

Com o backend no ar e as lojas autorizadas, o próximo passo é eu adicionar o botão
"Atualizar" dentro do Doca, apontando pra esses endpoints `/sync` e `/data` — isso é uma
mudança no arquivo do Doca, não nesse backend. Me avisa quando tiver essa parte pronta
(banco criado, backend no Render rodando, pelo menos uma loja autorizada) que eu sigo com
essa integração.

## Observações importantes

- O plano gratuito do Render "dorme" o serviço depois de um tempo sem uso — a primeira
  chamada depois de um tempo parado pode demorar uns 30-50 segundos pra responder (ele
  "acordando"). Isso é normal e não atrapalha o uso com botão de atualizar manual.
- Guarde o Client Secret de cada loja em local seguro — quem tiver ele consegue agir como
  se fosse a aplicação. Nunca cole ele em lugar público.
- Os endpoints usados pra buscar itens (`/users/{id}/items/search` e `/items?ids=...`) são os
  documentados oficialmente pelo Mercado Livre para consulta de anúncios/estoque do próprio
  vendedor. Se algum dia esses endpoints mudarem, é só me avisar que ajusto o `server.js`.
