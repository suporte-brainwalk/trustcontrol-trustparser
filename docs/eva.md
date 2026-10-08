# EVA — suporte e manutenção por IA do Trust Parser (por e-mail e API)

A EVA atende pedidos enviados para **eva-trustparser@trustcontrol.nuvem.tec.br** e pela **API do Trust Parser**
(`/api/v1/eva/conversations`). Ela segue o mesmo modelo do Jarbas do TrustRadar: código determinístico em volta, IA só
para entender, planejar, editar e redigir. Ela cuida de:
- **Suporte:** explica como funciona cada tela do Trust Parser (fontes, IPs liberados, destinos, parsers, Estúdio IA,
  uploads, não reconhecidos), com passo a passo numerado e telas de exemplo anexadas. Antes de responder, consulta os dados
  reais, como a situação de uma fonte, as linhas não reconhecidas ou as falhas de entrega de um destino.
- **Manutenção:** faz o que um administrador faz no painel (tabela abaixo).
- **Pedidos ao Estúdio IA:** um parser novo de entrada, um formato de saída novo ou o ajuste de um parser existente.
  A EVA **só faz o pedido**. A versão gerada fica em rascunho e **só vale depois que um administrador aprova e publica**.
- **Ajustes no produto:** telas, textos, formatação e lógica de exibição, publicados depois de testes e verificação visual.
- **Próximos passos** para o time.

O Rogério Crispim recebe cópia de todas as conversas. Quem estiver em **Para** ou **Cc** continua na conversa. As
respostas nunca citam nomes de fabricantes ou modelos de IA: dizem só "IA".

## Quem pode pedir
A lista é mantida por um administrador em **Trust Parser → EVA**.

| Papel | Quem (implantação) | Pode |
|---|---|---|
| Dono | rogerio.crispim@brainwalk.com.br, raphael.soares@trustcontrol.com.br | tudo o que o membro pode, mais **autorizar e remover membros** por e-mail à EVA ou pela API |
| Membro | alberto.santos@trustcontrol.com.br (e quem for autorizado) | pedir ajustes, manutenção e pedidos ao Estúdio, tirar dúvidas e desfazer |

- **Na tela EVA** o administrador inclui pessoas como dono ou membro, muda o papel e remove. Há uma trava: a lista nunca
  fica sem dono ativo, então o último dono não pode ser removido nem rebaixado. Os donos recebem um aviso por e-mail a
  cada mudança.
- **Por e-mail ou API** um dono só inclui ou remove **membros**. Donos são geridos só na tela.
- O e-mail precisa chegar **assinado (DKIM) pelo domínio do remetente**. A EVA confere a assinatura no e-mail original.
  Se um e-mail chega sem assinatura válida em nome de alguém da lista, ele é ignorado e o suporte é avisado, porque pode
  ser tentativa de fraude.
- **Modo:** no modo **demonstração** só o Rogério é atendido. No modo **ativo** toda a lista é atendida. O botão fica na
  tela EVA e funciona como freio de emergência.

## Como funciona
```
e-mail ─► orquestrador eva-orchestrator (código determinístico, a cada 60 s)
          assinatura DKIM + lista de autorizados (lida do banco a cada mensagem) → fila (um pedido por vez)
          ─► agente de IA em sandbox: entende o pedido (texto e imagens) e classifica
               pergunta · esclarecimento · alteração · manutenção · desfazer · autorizar/remover pessoa · fora de escopo
          ─► manutenção: o agente planeja operações e consulta os dados reais pela API de leitura
               → o Trust Parser SIMULA todas (tudo ou nada) → aplica com auditoria e retrato "antes" para desfazer
          ─► alteração: o agente edita uma cópia do código e escreve testes
          ─► orquestrador: política de áreas permitidas → todos os testes → Trust Parser temporário antes/depois
               (claro/escuro, computador/celular, sem erros) → até 3 tentativas de correção
          ─► publica: commit "EVA: …" no GitHub → nova imagem de parser-app e parser-ingest → verificação no ar
               (se falhar: volta sozinha à versão anterior)
          ─► resposta na mesma conversa (texto amigável, imagens antes/depois, próximos passos), Rogério em cópia
```
A IA só entende, planeja, altera, escolhe o que desfazer e redige. Leitura da caixa, assinatura, lista, simulação,
testes, publicação, reversão, envio de e-mail, lembretes e monitoramento são código determinístico.

## Manutenção (operações disponíveis)
| Área | Operações |
|---|---|
| Tenants | incluir, editar (nome, segmento, interno), suspender, reativar |
| Fontes | incluir (syslog, upload ou conector de API), editar (parser, filtro de hostname, linhas não reconhecidas, aviso de fonte parada), ativar, desativar |
| IPs liberados (syslog) | incluir (IP público único ou faixa de no máximo **/24**, com protocolo e validade opcional), desativar, reativar |
| Destinos | incluir **sem credencial**, editar, ativar, desativar, testar a conexão (envia um evento sintético) |
| Estúdio IA | pedir parser novo, formato de saída novo ou ajuste de parser. A publicação continua com o administrador |
| Pessoas do tenant | convidar gestor/leitor (convite por e-mail), reenviar convite, remover |

**A EVA nunca:**
- exclui tenant, fonte, destino ou IP: só desativa ou suspende;
- lê, pede ou grava **credenciais**. Uma operação com campo ou valor que pareça segredo é recusada inteira. Destino ou
  conector que precisa de credencial é criado inativo, e um administrador cadastra a credencial na tela e usa o botão
  **Testar**;
- libera faixa larga, IP privado ou `0.0.0.0/0`. Isso é decisão de um administrador na tela, que tem as próprias travas
  (até /16 com confirmação);
- publica ou altera um parser diretamente;
- mexe em administradores do portal, configurações, chaves de API, MFA, senhas, firewall do servidor ou outra infraestrutura.

O executor é `app/services/eva_maintenance.py`, que chama os mesmos serviços da tela e da API. A EVA não consegue editar
esse arquivo. O orquestrador o roda dentro do container da aplicação:
`docker exec -i parser-app python -m app.services.eva_maintenance --modo testar|aplicar|desfazer --solicitante <e-mail>`.

## O que a EVA pode e não pode alterar no código
- **Pode:** telas e e-mails (templates), estilos e scripts do portal, textos, formatação, a lógica de exibição
  (`app/web/admin.py`, `app/web/tenant.py`, `app/services/queries.py`) e testes.
- **Nunca:** dados; banco, modelos e migrações; login, MFA, permissões, sessões e CSP; configuração, variáveis de
  ambiente, segredos e criptografia; o motor de parsing e os parsers (`app/engine`), o receptor syslog e os conectores;
  a API; infraestrutura (Docker, nginx, Postfix, deploy, firewall); a própria EVA, sua tela e sua lista; enviar
  código-fonte por e-mail; assuntos fora do Trust Parser.

Essas regras são garantidas por 3 camadas independentes:
1. **Sandbox:** container sem segredos do Trust Parser, sem banco e sem Docker. Ele só lê fora da cópia do código, roda
   com usuário sem privilégios e tem rede **apenas para openrouter.ai**, pelo proxy `eva-egress` (squid). A chave da IA
   entra só por um arquivo de ambiente temporário (600), apagado ao fim.
2. **Agente:** usa apenas as ferramentas Ler/Buscar/Editar/Escrever, sem comandos e sem busca na web. O hook `guard.py`
   bloqueia qualquer caminho fora do permitido.
3. **Orquestrador:** recusa diffs fora das áreas permitidas ou com padrões proibidos (gravação no banco, SQL, rede,
   comandos, `|safe`, `<script>`, `config`, recursos externos, testes desativados). Também procura segredos reais no diff
   e em todo e-mail enviado, e não deixa a resposta afirmar que publicou algo que não foi publicado nem citar
   fabricante ou modelo de IA.

## IA
- **Harness:** o CLI do agente do servidor roda no sandbox apontado para o endpoint compatível do OpenRouter, com
  `ANTHROPIC_BASE_URL=https://openrouter.ai/api`, `ANTHROPIC_AUTH_TOKEN=<chave dedicada>` e `ANTHROPIC_API_KEY=""`.
  O modelo é **`xiaomi/mimo-v2.6-pro`** em `ANTHROPIC_MODEL`, `ANTHROPIC_DEFAULT_*_MODEL` e `ANTHROPIC_SMALL_FAST_MODEL`.
  Em 08/10/2026 confirmamos que o endpoint `/api/v1/messages` faz chamadas com ferramentas no MiMo.
- **Chave:** fica em `/root/trustparser/secrets/openrouter.env` (`OPENROUTER_API_KEY`, `OPENROUTER_MODEL`). O
  orquestrador relê o arquivo a cada uso, então a chave pode ser trocada sem reiniciar nada.
- **Retenção zero (ZDR):** as chamadas diretas do orquestrador, hoje só os lembretes, usam o endpoint de chat completions
  com `{"provider": {"zdr": true, "data_collection": "deny"}}`. O harness do agente não consegue enviar preferências de
  provedor. Nele, a restrição vem da **trava da própria chave dedicada no OpenRouter**, que só permite provedores ZDR para
  o modelo. Manter essa trava ligada no painel do OpenRouter é parte da operação.
- O heartbeat consulta a situação da chave (`GET /api/v1/key`, sem consumir tokens) a cada 5 minutos. Ele avisa se a
  chave falhar ou se o saldo do limite ficar abaixo de US$ 0,30 (`EVA_AI_KEY_MIN_USD`).

## Consulta de dados
A EVA lê os dados pela API v1 com uma **chave própria protegida** (`api_keys.ensure_eva_key()`), que tem escopo global,
só leitura e não pode ser revogada pelo portal. O agente não tem rede até o Trust Parser e nunca vê a chave. Ele pede
caminhos em `consultar_dados` (ex.: `/sources?tenant_id=3`, `/destinations/2/deliveries`). O orquestrador valida cada
caminho contra uma lista fechada de rotas de leitura (`tools/eva/orchestrator/dataapi.py`), faz o GET e devolve o
resultado. Por defesa extra, campos com nome de segredo saem como `[omitido]`. Limites: até 6 consultas por rodada e 2
rodadas.

## Conversa pela API
Quem pode falar com a EVA por e-mail também pode pela API, com os mesmos direitos, regras e proibições.

| Item | Regra |
|---|---|
| Quem fala | o **responsável** pela chave (`owner_email`), ativo na lista. O papel é conferido na criação da chave, a cada chamada e de novo ao processar |
| Autenticação | substitui o DKIM: chave global com `eva:conversar`, IPs de origem obrigatórios e MFA de quem criou a chave |
| Modo demonstração | igual ao e-mail: só o Rogério é atendido |
| Fila | a mesma do e-mail (`eva_requests`, `details.channel = "api"`), um pedido por vez |
| Limites | 3 pedidos na fila e 30 mensagens por hora por chave; 20 mil caracteres; até 4 imagens (5 MB) |
| Resposta | fica em `eva_messages` (texto, HTML igual ao e-mail, versão estruturada e telas). Com `email_copy`, também sai por e-mail |
| Gestão | `eva:ler` dá situação, conversas e lista. `eva:gerenciar` (só chave de dono) inclui/remove **membros** e muda a situação de uma conversa |

## Desfazer
Basta pedir na conversa ("volta como estava", "desfaz a liberação daquele IP"). A EVA escolhe entre as mudanças recentes
e pergunta se houver dúvida.
- **Alteração do produto:** vira `git revert`, passa pelas mesmas verificações e é publicada. Também dá para voltar
  qualquer versão pelo GitHub, já que cada mudança é um commit "EVA: …".
- **Manutenção:** o que foi incluído é desativado ou suspenso, nunca apagado. O que foi editado volta ao retrato "antes".
  Convite pendente é retirado. Pessoa removida é convidada de novo. Pedido ao Estúdio ainda na fila é cancelado. Se o
  Estúdio já gerou a versão, ela continua só em rascunho.

## Pendências e lembretes
Cada conversa tem um estado: em andamento, concluída, aguardando time Trust, aguardando Rogério ou parada. Sem resposta
em 2 dias úteis, a EVA manda um lembrete gentil, no máximo 2. Depois disso a conversa fica parada e o suporte é avisado.
Na tela EVA dá para encerrar uma conversa ou parar os lembretes.

## Operação
| Item | Onde |
|---|---|
| Containers | `eva-orchestrator` (orquestrador) e `eva-egress` (proxy de saída) em `/root/docker-compose.yml` (modelo em `deploy/eva/compose.snippet.yml`). O sandbox `eva-sbx-*` é criado a cada pedido a partir da imagem `eva-sandbox` |
| Redes | `trustparser_net` (orquestrador, parser-db, parser-app, postfix-mail, nginx-proxy), `eva_sandbox` (interna: sandbox ↔ eva-egress) e `eva_egress_out` (saída do squid) |
| Código | `tools/eva/` (orquestrador, sandbox, proxy, cenário de verificação, testes), `app/services/eva_*.py`, `app/api/routes/eva.py`, `app/web/eva.py` |
| Estado | `/srv/eva` (cópia de trabalho, pedidos recebidos, capturas, sessões do agente) e tabelas `eva_*` do banco `trustparser` |
| Credenciais | `/root/trustparser/secrets/eva.env` (600; `DATABASE_URL`, `EVA_MAIL_PASSWORD`, `EVA_API_KEY`), `eva-mail.env` (senha da caixa, entregue ao postfix-mail) e `openrouter.env` (chave da IA) |
| Caixa | `eva-trustparser@` no postfix-mail, com login IMAP só a partir de 172.29.0.0/24 e 127.0.0.0/8. A criação é feita por `deploy/eva/setup-mailbox.sh` |
| Publicação | repositório `/root/trustcontrol-trustparser` (GitHub `github-tc-trustparser`, branch `main`, autor "EVA <eva-trustparser@…>"), imagem `trustparser-app` (alvo `runtime`) nos serviços `parser-app` e `parser-ingest`. A imagem anterior fica em `trustparser-app:eva-anterior` |
| Modo | setting `eva_mode`: `demo` ou `ativo`, alterado na tela EVA |
| Painel | Trust Parser → EVA: status, modo, fila, conversas, histórico e lista de autorizados |

Comandos:
```bash
docker logs -f eva-orchestrator                                        # acompanhar
docker compose -f /root/docker-compose.yml restart eva-orchestrator
docker build -f tools/eva/Dockerfile.sandbox -t eva-sandbox:latest tools/eva   # sandbox (após atualizar)
docker compose -f /root/docker-compose.yml build eva-orchestrator && docker compose -f /root/docker-compose.yml up -d eva-orchestrator
docker exec eva-egress tail -n 50 /var/log/squid/access.log            # o que o sandbox tentou acessar (só openrouter.ai passa)
```

Avisos automáticos vão para **suporte.trustcontrol@brainwalk.com.br** (`EVA_ALERT_TO`), no máximo 1 por tipo a cada
6 horas. O Rogério continua em cópia das conversas. Os avisos cobrem:
- acesso à IA falhou ou saldo da chave baixo;
- caixa ou envio de e-mail com problema;
- pedido travado ou falho;
- publicação bloqueada ou revertida;
- e-mail rejeitado por assinatura;
- disco baixo;
- conversa parada.

## Testes
- **Determinísticos** (sem IA, rede ou banco): caminhos, hook, política, segredos, DKIM com assinaturas reais, regras de
  lista, estado e lembretes, e-mails, proxy só para openrouter.ai, ZDR nas chamadas diretas, regra de saúde da
  publicação e travas da manutenção (IP, credenciais).
  `/root/trustparser/venv/bin/python -m pytest tools/eva/tests -q -p no:cacheprovider --noconftest`
- **Ponta a ponta:** use uma instância de teste do orquestrador com `EVA_DRY_RUN_DEPLOY=1`, `EVA_OUTBOUND_REDIRECT=<caixa>`,
  `EVA_STATE_DIR=/srv/eva-e2e` e `EVA_IMAP_KEYWORD=EvaE2E`, e remetentes de teste assinados pelo OpenDKIM local, no mesmo
  roteiro do Jarbas.
