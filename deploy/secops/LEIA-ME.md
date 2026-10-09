# Parsers para importar no Google SecOps (CBN)

Use quando o Google SecOps for receber os logs **diretamente** (sem o Trust Parser no meio) e precisar entender um formato
personalizado. Cada arquivo `.conf` é um parser personalizado no padrão do SecOps (CBN).

## Passo a passo (exemplo: Nginx, formato " | ")
1. No SecOps: **Configurações do SIEM → Parsers** (ou "Parsers" no menu de configurações).
2. Localize o tipo de log **NGINX** (ou o tipo de log usado na ingestão) → **Criar parser personalizado** (Create custom parser).
3. Escolha começar do zero / colar código e cole o conteúdo de `nginx-access-pipe.conf`.
4. Em **Amostras de log**, carregue de 10 a 50 linhas reais e clique em **Preview / Validate**: os eventos devem sair como
   `NETWORK_HTTP` com principal.ip, target.hostname, target.url, network.http.method e response_code preenchidos.
5. **Submit / Ativar**. O SecOps passa a usar este parser para as novas linhas desse tipo de log (o parser padrão do Google
   para NGINX espera o formato "combined" e não entende o formato " | ").
6. Garanta que os logs chegam ao SecOps com o tipo de log **NGINX** (no forwarder/coletor, campo `log_type`/"Log type").

Observações: o parser foi validado no Trust Parser com 3.306 linhas reais (100%); a sintaxe CBN deve ser conferida no
"Validate" do próprio SecOps antes de ativar. Se o log_format do Nginx mudar, peça um novo parser.
