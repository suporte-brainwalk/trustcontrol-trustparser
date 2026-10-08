# Trust Parser — linguagem dos parsers (spec JSON) e modelo canônico

Cada parser de entrada é um JSON executado pelo motor `app/engine/dsl.py`. **Determinístico**: mesma linha + mesmo spec =
mesmo evento. A IA do Estúdio só escreve specs; quem executa é o motor. Exemplos completos e reais:
`app/engine/builtin/nginx_access_trust.json` e `app/engine/builtin/withsecure_elements.json`.

## 1. Estrutura

```json
{
  "slug": "fabricante-produto-formato",        // único, minúsculas e hífens
  "name": "Fabricante Produto · descrição curta",
  "vendor": "Fabricante", "product": "Produto",
  "description": "Como a linha chega e o que cobre (pt-BR)",
  "basis": "real | docs",                      // real = feito com amostra real; docs = só documentação
  "priority": 100,                             // ordem na autodetecção (menor primeiro)
  "detect": { condição sobre "$raw" },        // reconhece o formato (autodetecção)
  "steps": [ ...extrações... ],
  "map": { "campo.canonico": expressão, ... }, // mapeamento base
  "cases": [ {"name": "...", "when": condição, "unset": ["caminho"], "map": {...}, "continue": false} ],
  "unmapped": ["kv"],                          // blocos extraídos copiados para "unmapped" (nada se perde)
  "unmapped_drop": ["chave"],                  // chaves desses blocos que não vão para unmapped
  "require": ["time", "metadata.event_code"],  // obrigatórios; senão a linha vai para "Não reconhecidos"
  "tests": [ {"name": "...", "input": "linha bruta", "expect": {"caminho": valor, ...}} ]
}
```

O contexto de execução começa com `$raw` (a linha) e `$meta` (IP de origem, transporte, hostname do syslog). Cada passo
grava o resultado em `to` (caminho pontuado). Caminhos leem dicionários e listas (`a.b.0.c`).

## 2. Passos (`steps`)

Todos aceitam `from` (expressão; padrão `$raw`), `to`, `when` (condição para rodar) e `optional: true` (falha não derruba a linha).

| op | o que faz | parâmetros |
|---|---|---|
| `json` | JSON → objeto | `seek: true` procura o primeiro `{` |
| `syslog` | cabeçalho RFC 5424/3164 → `{pri, facility, severity, timestamp, hostname, app, procid, msgid, sd, msg, format}` | `optional: true` devolve `{msg: linha}` sem cabeçalho |
| `regex` | grupos nomeados `(?P<nome>…)` → objeto | `pattern`, `name` (rótulo do erro) |
| `split` | separa por `sep` e nomeia | `sep`, `names`, `min_fields`, `exact`, `unquote` (padrão true), excesso vai em `_extra` |
| `kv` | chave=valor | `mode: "simple"` (`pair_sep`, `kv_sep`, aspas opcionais) ou `"quoted"` (`chave="valor"` tolerante a aspas internas sem escape), `strip_prefix` |
| `cef` | CEF:0 → `{version, device_vendor, device_product, device_version, signature_id, name, severity, ext:{...}}`; `csNLabel` vira chave | |
| `leef` | LEEF 1.0/2.0 → `{version, vendor, product, product_version, event_id, ext:{...}}` | |
| `csv` | uma linha CSV | `names`, `delimiter` |
| `winxml` | XML de evento Windows → `{System:{EventID, Channel, Computer, ProviderName, TimeCreatedSystemTime, EventRecordID…}, EventData:{Nome: valor}}` | |
| `url` | URL → `{url_string, scheme, hostname, port, path, query_string}` | |
| `list` | texto → lista | `type` (padrão `split:,`) |
| `set` | grava o valor de uma expressão | `value` |
| `mojibake` | corrige UTF-8 lido como Latin-1 ("InformaÃ§Ãµes" → "Informações") | `paths` (objetos ou campos) |

## 3. Expressões (valores do `map`)

| forma | resultado |
|---|---|
| `"kv.campo"` | valor do caminho |
| `{"const": 4002}` | constante |
| `{"path": "f.status", "type": "int"}` | caminho + conversões |
| `{"first": [expr, expr]}` | primeiro valor não vazio |
| `{"template": "{a.b} - {c}", "strict": true}` | texto; `strict` = nulo se faltar algum campo |
| `{"lookup": expr, "table": {"a": 1}, "default": 0}` | tabela de tradução |
| `{"regex": "^(\\d)", "path": "f.status", "group": 1}` | trecho por regex |
| `{"url": expr}` | objeto URL |
| `{"object": {"k": expr}}` / `{"list": [expr]}` | objeto / lista (vazios somem) |

**Conversões (`type`, string ou lista em sequência):** `str int float bool lower upper strip unquote nil` (`-`/vazio → nulo),
`ip` (valida; tira `/24` e `:porta`), `ips` (lista de IPs válidos), `split:<sep>`, `first`, `last`,
`time` (ISO/epoch automático), `epoch_ms`, `epoch_s`, `strptime:<formato Python>`, `mojibake`, `basename`, `dirname`,
`domain` (`DOM\usuario` → `DOM`), `user` (`DOM\usuario`/`usuario@dom` → `usuario`), `url_host`,
`key:<chave>` (objeto → valor da chave literal, para chaves com ponto: `{"path": "j.detection", "type": "key:open.date"}`),
`join:<sep>` (lista → texto unido por `sep`, padrão `", "`; itens vazios e objetos são ignorados; texto passa intacto),
`pick:<campo>=<valor>` (lista de objetos → primeiro objeto com `campo` igual a `valor`; ex.: `["pick:entityType=host", "key:entityValue"]`),
`hash_alg` (hash hexadecimal → `MD5`/`SHA-1`/`SHA-256`/`SHA-512` pelo tamanho; nulo se não for hash — útil para
`{"object": {"algorithm": {"path": "x.hash", "type": "hash_alg"}, "value": "x.hash"}}` sumir quando não há hash),
`replace:<antigo>:<novo>` (troca literal; o primeiro `:` separa os dois; ex.: `"replace:#011:\t"` desfaz o escape de TAB do rsyslog).

Valores vazios (`None`, `""`, `"-"`, `[]`, `{}`) nunca são gravados no evento.

## 4. Condições (`detect`, `when`)

`{"path": "kv.eventType", "eq": "x"}` · `ne` · `in: [..]` · `re: "regex"` · `startswith` · `contains` · `exists: true|false` ·
`{"all": [..]}` · `{"any": [..]}` · `{"not": cond}`. Sem `path`, vale `$raw`.

## 5. Modelo canônico (OCSF 1.3, subconjunto)

| campo | uso |
|---|---|
| `time` | ISO-8601 UTC com ms (**obrigatório**) |
| `class_uid`, `class_name`, `category_uid`, `category_name` | classe OCSF: 4002 HTTP Activity, 4001 Network Activity, 4003 DNS Activity, 3002 Authentication, 3001 Account Change, 3006 Group Management, 1007 Process Activity, 1001 File System Activity, 1008 Event Log Activity, 2004 Detection Finding, 2002 Vulnerability Finding, 0 Base Event |
| `activity_id`, `activity_name`, `type_uid` (calculado) | atividade |
| `severity_id` (0–6) → `severity` (calculado) | 1 Informational, 2 Low, 3 Medium, 4 High, 5 Critical |
| `status` (Success/Failure), `status_id`, `status_code`, `status_detail` | resultado |
| `disposition` (Allowed/Blocked/Quarantined/Deleted/Detected…), `disposition_id`, `action` (Allowed/Denied), `action_id` | decisão do controle |
| `message` | resumo legível |
| `metadata.product.vendor_name`, `metadata.product.name`, `metadata.product.version` | origem |
| `metadata.event_code`, `metadata.event_subtype`, `metadata.log_name`, `metadata.uid`, `metadata.logged_time` | identificação |
| `src_endpoint.{ip,port,hostname}`, `dst_endpoint.{ip,port,hostname}`, `proxy_endpoint.ip` | rede |
| `device.{hostname,uid,ip,ips,domain,os,org.name,logged_user}` | equipamento que gerou o evento |
| `actor.user.{name,domain,uid,full_name,email_addr}`, `actor.process.{name,path,pid,cmd_line}` | quem agiu |
| `user.{name,domain,uid,email_addr,display_name}`, `group.{name,domain,uid}` | usuário/grupo alvo |
| `process.{name,path,pid,cmd_line,file.{path,name,hashes,signer,...}}` | processo alvo |
| `file.{name,path,size,hashes:[{algorithm,value}],created_time,modified_time}` | arquivo alvo |
| `http_request.{http_method,version,user_agent,referrer,x_forwarded_for,url.{url_string,scheme,hostname,path,query_string,categories}}` | HTTP |
| `http_response.{code,length}`, `tls.{version,cipher}` | HTTP |
| `connection_info.{protocol_name,direction}`, `traffic.{bytes_in,bytes_out,packets_in,packets_out}` | conexão |
| `finding_info.{title,uid,desc,types}`, `malware:[{name,classification}]`, `vulnerabilities:[{cve, severity, title}]` | achados |
| `policy.{name,uid,version}`, `rule.{name,uid,type}` | política/regra |
| `observer.hostname` | coletor/relay que enviou (ex.: conector) |
| `logon_type_id`, `auth_protocol`, `logon_process.name` | autenticação |
| `unmapped` | tudo o que foi extraído e não mapeado |

Os formatos de saída (UDM, Wazuh, CEF, LEEF, CSV, OCSF) partem só destes campos — mapeie neles para a saída ficar rica.

## 6. Formatos de saída personalizados (Estúdio → Nova saída)

```json
{"serializer": "json | kv | csv | template | cef | leef",
 "map": {"campo.destino": expressão sobre "e.<campo canônico>", "raw" ou "ctx.tenant"},
 "template": "texto com {e.time} ...",          // só serializer=template
 "header": {"vendor": "...", "product": "...", "event_id": expr, "name": expr, "severity": expr},  // cef/leef
 "columns": ["a", "b"], "delimiter": ","}       // csv
```

## 7. Testes

Cada spec traz `tests`: linha + campos esperados (`{"http_response.code": 200}`). Publicar exige 100% dos testes ok e a
cobertura das amostras exibida na tela. Uma versão nova nunca substitui a anterior sem aprovação de administrador.
