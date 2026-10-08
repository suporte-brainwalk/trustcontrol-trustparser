# Conectores API PULL

Os conectores coletam eventos de produtos SaaS de segurança diretamente pelas APIs dos fabricantes e entregam **uma
linha JSON por objeto** ao parser builtin correspondente. Código: `app/engine/connectors/` · testes:
`tests/unit/test_connectors.py`.

> **Importante — validação pendente.** Todos os conectores foram escritos a partir da documentação pública dos
> fabricantes (pesquisa de 08/10/2026 em `/root/trustparser/research/`) e testados apenas contra respostas simuladas
> (`httpx.MockTransport`). **Nenhum foi validado com credenciais reais.** Antes de colocar um cliente em produção,
> rode o botão *Testar conexão* e uma coleta manual, e confira os objetos recebidos contra o parser.

## Comportamento comum

| Item | Valor |
|---|---|
| Cliente HTTP | `httpx`, timeout de conexão 10 s e de leitura 30 s, `User-Agent: TrustParser/1.0`, TLS sempre verificado, redirects **não** seguidos |
| Retry | Até 3 tentativas em HTTP 429/500/502/503/504 e erros de rede; respeita `Retry-After` (teto de 60 s); sem cabeçalho, espera 1 s e depois 2 s |
| Erros | `ConnectorError` com mensagem em pt-BR, exibível ao usuário. HTTP 401/403 viram "Credenciais recusadas pelo &lt;fabricante&gt; (HTTP 401)…". Os valores dos segredos são removidos de qualquer trecho de resposta incluído na mensagem |
| Logs | Registram só o método, o caminho e o status. Cabeçalhos, tokens e segredos nunca são registrados |
| Limite por chamada | No máximo **5.000 objetos** por `pull()`. Acima disso, `more=True` e o agendador deve chamar de novo logo em seguida |
| Primeira coleta | Com o cursor vazio, a coleta volta só `lookback_minutes` minutos (padrão 60; Tenable usa 1440) |
| Cursor | Um dict JSON persistido entre execuções. Nos conectores com watermark, guarda `since` (ISO UTC) e `boundary` (ids já vistos exatamente no instante `since`, para não duplicar). Quando a janela fica sem eventos, o `since` avança até agora − 2 min |
| Linhas | `json.dumps(obj, ensure_ascii=False, separators=(",", ":"))`: o objeto da API sem alteração, exceto no WatchGuard (ver abaixo) |

API Python: `from app.engine.connectors import get` → `get(slug).test(config, secrets)` e
`get(slug).pull(config, secrets, cursor)`. As duas chamadas aceitam `client=` (um `httpx.Client` injetável).
`get(slug).schema()` devolve os campos para montar o formulário.

Resumo:

| Slug | Produto | Parser | Intervalo padrão |
|---|---|---|---|
| `withsecure-elements` | WithSecure Elements (Security Events) | `withsecure-elements-api-event` | 5 min |
| `cortex-xdr` | Palo Alto Cortex XDR (alertas) | `cortex-xdr-api-alert` | 5 min |
| `trend-vision-one` | Trend Vision One (Workbench / OAT) | `trend-vision-one-api-alert` | 5 min |
| `watchguard-epdr` | WatchGuard Endpoint Security (EPDR) | `watchguard-epdr-api-json` | 10 min |
| `axur` | Axur (tickets) | `axur-api-ticket` | 10 min |
| `tenable` | Tenable Vulnerability Management / Security Center | `tenable-vuln-export` | 60 min |

---

## 1. WithSecure Elements — `withsecure-elements`

**O que cadastrar na GUI**

| Campo | Obrigatório | Onde obter |
|---|---|---|
| URL da API | não (padrão `https://api.connect.withsecure.com`) | Só mude se a WithSecure indicar outro host |
| Client ID | sim | Elements Security Center → *Organization settings* → *API clients* → *Add new*. Marque **somente leitura** (escopo `connect.api.read`) |
| Organization ID | não | UUID da organização. Vazio usa a organização padrão do API client. Para parceiros, inclui as organizações filhas |
| Grupos de engine | não (padrão `epp,edr,ecp,xm`) | Lista entre `epp`, `edr`, `ecp` e `xm` |
| Retroativo na 1ª coleta | não (60) | Minutos |
| **Client Secret** (segredo) | sim | Exibido uma única vez, quando o API client é criado |

Permissão: um API client de leitura basta. A conta precisa dos módulos cujos eventos serão lidos (EPP/EDR/ECP/XM).

**Endpoints**
- `POST /as/token.oauth2`: Basic `client_id:secret`, `grant_type=client_credentials&scope=connect.api.read`. O token é pedido a cada execução.
- `POST /security-events/v1/security-events` (form-urlencoded): `persistenceTimestampStart` = cursor, `persistenceTimestampEnd` = agora (no máximo 30 dias depois do início), `engineGroup` repetido, `order=asc`, `limit=200`, `organizationId`. A paginação segue `anchor`/`nextAnchor`.
- Cursor: o `persistenceTimestamp` do último evento, com dedupe por `id` na fronteira.

**Limitações e incertezas**
- O limite de requisições pode ser 300 ou 10.000 por minuto por IP (a documentação é ambígua). Com 5 min de intervalo e 200 eventos por página, o uso fica bem abaixo dos dois.
- O corpo do POST está documentado como form-urlencoded, mas o poller oficial do Sentinel envia JSON. Usamos form; se a API recusar, troque para JSON.
- Há duas variantes de envelope (`organization` com datas ISO, ou `account` com epoch ms). O parser precisa aceitar as duas.
- Se o cursor ficar mais de 30 dias para trás, a coleta avança em janelas de 30 dias, com `more=True`.

---

## 2. Cortex XDR — `cortex-xdr`

**O que cadastrar na GUI**

| Campo | Obrigatório | Onde obter |
|---|---|---|
| URL da API (FQDN) | sim | *Settings → Configurations → Integrations → API Keys* → **Copy API URL** (ex.: `https://api-empresa.xdr.us.paloaltonetworks.com`). Aceita só o host e acrescenta `api-` se faltar |
| API Key ID | sim | Coluna **ID** da chave na lista de API Keys (número) |
| Tipo de chave | sim | *Advanced* (padrão, recomendado) ou *Standard*, conforme o **Security Level** escolhido ao gerar a chave |
| Endpoint de alertas | não | `get_alerts_multi_events` v2 (padrão), v1 legado ou `get_alerts` v1 |
| Retroativo na 1ª coleta | não (60) | Minutos |
| **API Key** (segredo) | sim | Exibida uma única vez ao gerar a chave |

Permissão: gere a chave com um papel de leitura que inclua alertas (por exemplo, **Viewer** ou um papel customizado com
"Alerts/Incidents – view"). A licença precisa incluir a API pública: sem ela, a API devolve HTTP 402, que é mostrado ao usuário.

**Endpoints**
- `POST https://api-<fqdn>/public_api/v2/alerts/get_alerts_multi_events` (ou o endpoint v1 escolhido), corpo `{"request_data": {"filters": [server_creation_time gte <cursor>, lte <agora>], "search_from", "search_to", "sort": {"field": "creation_time", "keyword": "asc"}}}`, em páginas de 100.
- Autenticação Advanced: `Authorization = sha256(api_key + nonce(64) + timestamp_ms)` com `x-xdr-nonce`, `x-xdr-timestamp` e `x-xdr-auth-id`. Standard: `Authorization = api_key` e `x-xdr-auth-id`.
- Cursor: o maior `local_insert_ts`, com dedupe por `alert_id`. A API só ordena por `creation_time`. Por isso, quando o limite de 5.000 é atingido no meio de uma janela, o cursor guarda a janela fixa e o offset (`resume`) e só avança o watermark quando a janela inteira foi lida.

**Limitações e incertezas**
- O limite é de 10 requisições por segundo por tenant. O status HTTP do excesso não está documentado; assumimos 429.
- A documentação da v2 lista só `filters`; o suporte a `search_from`/`search_to`/`sort` foi deduzido das integrações XSOAR e Elastic. Se a v2 ignorar a paginação, use o endpoint v1.
- A API não pagina além de cerca de 10.000 resultados por consulta. Uma janela maior que isso gera uma nota de possível perda.
- No Cortex 5.x, Alerts passou a se chamar Issues (`/public_api/v1/issue/search`), e esse endpoint não está implementado. Os campos da v2 chegam como arrays (`host_ip`, `user_name`, …).
- Incidentes e auditoria não são coletados nesta versão.

---

## 3. Trend Vision One — `trend-vision-one`

**O que cadastrar na GUI**

| Campo | Obrigatório | Onde obter |
|---|---|---|
| Região do console | sim | Região do tenant: EUA, UE, Singapura, Japão, Austrália, Índia, MEA, Reino Unido, Canadá ou US Gov. A URL aparece em *Administration → API Keys* |
| URL base | não | Sobrepõe a região (só se a Trend indicar outro host) |
| Dados coletados | não | *Workbench alerts* (padrão) ou *Workbench + OAT detections* |
| Critério de tempo | não | `createdDateTime` (só alertas novos, padrão) ou `updatedDateTime` (reenvia o alerta quando ele muda de status; o dedupe é por id + updatedDateTime) |
| Filtro TMV1-Filter | não | Sintaxe OData, por exemplo `severity eq 'high' or severity eq 'critical'`. Vale só para o Workbench |
| Retroativo na 1ª coleta | não (60) | Minutos |
| **API Key (token)** (segredo) | sim | *Administration → API Keys → Add API key*, com prazo de validade e um papel |

Permissão: o papel da chave precisa de *Workbench → View, filter, and search*. Para OAT, também *Observed Attack
Techniques → View*. Anote a data de expiração da chave: quando ela vence, a coleta passa a falhar com HTTP 401.

**Endpoints**
- `GET /v3.0/workbench/alerts?startDateTime&endDateTime&dateTimeTarget&orderBy=<alvo> asc`, com `Authorization: Bearer`. A paginação segue `nextLink`, e o `TMV1-Filter` é reenviado em cada página.
- Opcional: `GET /v3.0/oat/detections?ingestedStartDateTime&ingestedEndDateTime&detectedStartDateTime(-7 dias)&top=200` + `nextLink`.
- Cursor separado por fluxo (`workbench` e `oat`). Quando o limite é atingido, o cursor guarda a URL da página e quantos itens dela já foram lidos. Um `nextLink` para outro host é recusado e não recebe o token.

**Limitações e incertezas**
- Os limites por endpoint não são públicos; a API devolve 429 e o conector faz o backoff. O Workbench pagina de 10 em 10.
- Os objetos OAT têm outro formato (`filters[]`, `detail{}`, `uuid`) e usam o **mesmo parser** (`trend-vision-one-api-alert`), que precisa reconhecer os dois formatos. Não acrescentamos nenhum campo de marcação.
- A API de OAT usa a última 1 h como padrão para a janela de detecção. Enviamos uma janela de detecção de 7 dias junto com a de ingestão; o efeito combinado não está documentado.
- Para volume alto de OAT ou telemetria, a Trend recomenda *data pipelines*, que não estão implementados.

---

## 4. WatchGuard Endpoint Security (EPDR) — `watchguard-epdr`

**O que cadastrar na GUI**

| Campo | Obrigatório | Onde obter |
|---|---|---|
| Região do WatchGuard Cloud | sim | `usa`, `deu` ou `jpn`. *Administration → Managed Access* mostra a "API base URL" da conta |
| URL base da API | não | Sobrepõe a região (ex.: `https://api.usa.cloud.watchguard.com`) |
| Account ID | sim | *Administration → Managed Access* (ex.: `WGC-1-123abc456` ou `ACC-1234567`) |
| Access ID (somente leitura) | sim | *Administration → Managed Access → API*: **Read-only Access ID** |
| Plataforma | não | WatchGuard Endpoint Security (padrão) ou Panda Aether (AD360/AD/EP) |
| Tipos de evento | não (`1-19`) | 1 Malware, 2 PUPs, 3 Programas bloqueados, 4 Exploits, 5 Políticas avançadas, 6–14 detecções de antivírus, 15 Intrusão, 16 Conexões bloqueadas, 17 Dispositivos bloqueados, 18 Indicators of Attack, 19 Network Attack Protection |
| Retroativo na 1ª coleta | não (60) | Minutos |
| **Senha do Access ID** (segredo) | sim | Senha definida para o Read-only Access ID |
| **API Key** (segredo) | sim | *Administration → Managed Access → API Key* |

Permissão: o Read-only Access ID basta, e a conta precisa ter a API do WatchGuard Cloud habilitada.

**Endpoints**
- `POST /oauth/token`: Basic `AccessID:senha`, `grant_type=client_credentials&scope=api-access`.
- `GET /rest/endpoint-security/management/api/v1/accounts/{accountId}/securityevents/{tipo}/export/1`, ou o prefixo Aether `/rest/aether-endpoint-security/aether-mgmt/api/v1`. Um GET por tipo, com `Authorization: Bearer` e `WatchGuard-API-Key`.
- **A API não tem cursor nem filtro de tempo.** Cada coleta relê as últimas 24 h de cada tipo. O cursor guarda hashes curtos (`sha1(tipo|event_id|device_id)[:16]`) dos eventos já enviados, por 72 h e até 30.000 entradas, e descarta os repetidos. Na primeira coleta, os eventos anteriores ao retroativo ficam marcados como vistos e não são enviados.
- Cada linha recebe dois campos extras quando eles não existem no objeto: `security_event_type` (1–19) e `security_event_type_name`. O endpoint não informa o tipo no objeto.

**Limitações e incertezas**
- **Cada chamada devolve no máximo 3.000 registros** (cobrindo 24 h). Se um tipo chegar ao teto, a nota da coleta avisa que pode haver perda; nesse caso, reduza o intervalo.
- O formato JSON real foi **deduzido**: o exemplo da documentação nem é um JSON válido. O conector aceita `{"data": [...]}` ou uma lista pura.
- O status HTTP do limite de requisições (500 por segundo, 200.000 por dia) não está documentado.
- A região `deu` segue a WatchGuard; o guia do Google cita `api.eu`. Se o DNS falhar, use a URL base.
- Para telemetria completa, o caminho oficial é o SIEMFeeder (syslog), que não está neste conector.

---

## 5. Axur — `axur`

**O que cadastrar na GUI**

| Campo | Obrigatório | Onde obter |
|---|---|---|
| URL da API | não (padrão `https://api.axur.com/gateway/1.0/api`) | — |
| Customer key | não | Para MSSP/parceiro: a chave do cliente filho (ex.: `ACME`), enviada como `ticket.customer` |
| Filtros adicionais | não | Query string extra da Tickets API, por exemplo `current.type=phishing,fraudulent-brand-use`. Os parâmetros de paginação e de data são ignorados |
| Retroativo na 1ª coleta | não (60) | Minutos |
| **API Key** (segredo) | sim | Axur One → *Minhas preferências* → **API KEY** (`https://one.axur.com/preferences?tab=api-keys`) |

Permissão: a chave pertence ao usuário que a criou e herda as permissões dele (Viewer, Practitioner, Expert…). Use um
usuário de serviço que enxergue todos os ativos e tipos de ticket desejados. **Se esse usuário for desativado, a chave
é revogada** e a coleta passa a falhar com HTTP 401.

**Endpoints**
- `GET /tickets-api/tickets?ticket.last-update.date=ge:<cursor>&sortBy=ticket.last-update.date&order=asc&timezone=Z&pageSize=200&page=N`, com `Authorization: Bearer`.
- Cursor: o maior `ticket.last-update.date`, com dedupe por `ticketKey` + data de atualização. O mesmo ticket é reenviado sempre que é atualizado.

**Limitações e incertezas**
- O tamanho máximo de página e o limite numérico de requisições não estão documentados (a API devolve 429). Usamos 200 itens por página, como nos exemplos.
- O filtro `ticket.last-update.date` com `sortBy` foi deduzido da especificação, que não traz uma receita de coleta incremental. A granularidade é de segundos.
- O *Integration Feed* (cursor no servidor, exige permissão Manager), as exposições de credenciais e cartões (*Exposure API*) e os webhooks não estão implementados.
- Os payloads podem conter dados sensíveis (senhas vazadas, cartões); o parser ou o destino devem mascará-los.

---

## 6. Tenable — `tenable`

**O que cadastrar na GUI**

| Campo | Obrigatório | Onde obter |
|---|---|---|
| Plataforma | sim | *Vulnerability Management* (nuvem, padrão) ou *Security Center* (on-prem) |
| URL base | VM: não (padrão `https://cloud.tenable.com`; FedRAMP: `https://fedcloud.tenable.com`) · SC: **sim** (`https://<host-do-sc>`) | — |
| Severidades | não (`low,medium,high,critical`) | Inclua `info` se quiser os achados informativos (o volume é muito maior) |
| Ativos por chunk (VM) | não (500) | De 50 a 5000 |
| Retroativo na 1ª coleta | não (**1440**) | Minutos |
| **Access Key** e **Secret Key** (segredos) | sim | VM: *Settings → My Account → API Keys → Generate*. SC: *Users → (usuário) → Generate API Keys*. A autenticação por API key precisa estar habilitada no SC (≥ 5.13) |

Permissão (VM): um usuário de serviço **exclusivo** para o Trust Parser, com papel Basic e permissão de exportação de
vulnerabilidades (`VM.VM_EXPLORE…EXPORT`), além de *Can View* nos ativos. O Tenable impede exportações duplicadas
simultâneas por usuário (HTTP 409). SC: um usuário com acesso de leitura aos repositórios desejados.

**Endpoints: Vulnerability Management**
- `POST /vulns/export` com `filters.since` = cursor, `state=[OPEN, REOPENED, FIXED]`, `severity`, `num_assets`, e cabeçalho `X-ApiKeys: accessKey=…;secretKey=…`.
- `GET /vulns/export/{uuid}/status`: os chunks em `chunks_available` são baixados por `GET /vulns/export/{uuid}/chunks/{id}`. Cada item é uma linha.
- O job em andamento fica no cursor (`job`: uuid, criação, chunks concluídos, chunk parcial). As chamadas seguintes retomam o mesmo job, sem criar outro. Quando ele termina, `since` passa a ser o instante de criação do job. Um job com mais de 20 h é abandonado e recriado, porque os chunks expiram em cerca de 24 h.
- `test()` usa `GET /session`.

**Endpoints: Security Center** (implementação simples)
- `POST /rest/analysis` com `type=vuln`, `tool=vulndetails`, `sourceType=cumulative`, filtro `lastSeen = "<início>-<fim>"` (epoch), severidade, ordem por `lastSeen` e paginação `startOffset`/`endOffset` de 1.000. O cabeçalho é `x-apikey: accesskey=…; secretkey=…;`.
- `test()` usa `GET /rest/currentUser`.

**Limitações e incertezas**
- A coleta é de **estado de vulnerabilidades**, não de eventos: o mesmo achado volta quando é revisto (`last_found`) ou muda de estado. O dedupe ou upsert deve ser feito no destino, por `finding_id` ou por `asset.uuid + plugin.id + port + protocol`.
- Uma exportação pode levar vários minutos. Enquanto ela processa, a coleta devolve 0 linhas e avisa na nota.
- No SC, o valor `tool=vulndetails` e a sintaxe de intervalo absoluto do filtro `lastSeen` **não foram confirmados** na documentação. Valide com um SC real. Certificados autoassinados **não** são aceitos (TLS sempre verificado): o SC precisa de um certificado válido.
- O host FedRAMP não foi confirmado em developer.tenable.com. O caminho de cancelamento de exportação não é usado.
