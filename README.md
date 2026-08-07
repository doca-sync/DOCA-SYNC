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
