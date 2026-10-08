# Trust Parser

Parser de logs e eventos de segurança da Trust Control: recebe por **syslog** (TLS 6514, TCP/UDP 514), **conectores de API**
(WithSecure, Cortex XDR, Vision One, WatchGuard EPDR, Axur, Tenable) ou **upload**; normaliza cada linha de forma
**determinística** para um modelo canônico (OCSF); entrega no formato de cada destino (**Google SecOps UDM**, **Wazuh**,
**QRadar LEEF**, CEF, OCSF, CSV, syslog, webhook) ou para download. Novos formatos de entrada e saída são gerados pelo
**Estúdio IA** (a IA escreve o parser declarativo, o motor testa, um administrador publica). Suporte por IA: **EVA**.

- Portal e API: https://trustparser.trustcontrol.nuvem.tec.br — API em `/api/v1`, documentação em `/api/docs`
- Linguagem dos parsers e modelo canônico: [docs/dsl.md](docs/dsl.md) · Parsers embutidos: [docs/parsers.md](docs/parsers.md)
- Conectores: [docs/conectores.md](docs/conectores.md) · EVA: [docs/eva.md](docs/eva.md) · Operação: [docs/operacao.md](docs/operacao.md)
- Plano aprovado: [docs/PLANO.md](docs/PLANO.md) · Histórico da implantação: [docs/historico-implantacao-2026-10-08.md](docs/historico-implantacao-2026-10-08.md)
