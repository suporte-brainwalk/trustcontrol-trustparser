"""Esquemas (Pydantic v2) da API da EVA: situação, conversas, lista de autorizados e conversa (pedidos como por e-mail)."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import Field

from .schemas import In, Out, PageQuery, Query

ThreadState = Literal["em_andamento", "concluido", "aguardando_trust", "aguardando_rogerio", "parado"]


class EvaStatus(Out):
    online: bool = Field(description="Sinal de vida da EVA nos últimos 5 minutos.")
    last_signal_at: datetime | None
    mode: Literal["ativo", "demo"] = Field(description="ativo = atende toda a lista de autorizados; demo = só o Rogério (freio de emergência).")
    queued: int = Field(description="Pedidos na fila.")
    processing: int
    processing_request: int | None = Field(description="Pedido em execução agora.")
    ai_access_ok: bool | None = Field(description="Acesso da EVA ao serviço de IA válido.")
    email_in_ok: bool | None
    email_out_ok: bool | None


class EvaWhitelistEntry(Out):
    email: str
    name: str
    role: Literal["owner", "member"] = Field(description="owner = dono (altera a lista); member = pode pedir.")
    active: bool
    added_by: str
    added_at: datetime


class EvaRequestOut(Out):
    id: int
    channel: Literal["email", "api"]
    sender: str
    subject: str
    received_at: datetime
    status: Literal["queued", "processing", "done", "failed"]
    intent: str = Field(description="Tipo do pedido identificado pela EVA (pergunta, manutencao, alteracao…).")
    summary: str = Field(description="Resumo do que foi feito (sem o conteúdo dos e-mails).")
    commit: str | None = Field(description="Commit publicado, quando houve alteração do Trust Parser.")
    deployed: bool
    rolled_back: bool
    finished_at: datetime | None


class EvaThreadOut(Out):
    id: int
    subject: str
    requester: str
    state: ThreadState
    pending: list[str] = Field(description="Próximos passos em aberto.")
    created_at: datetime
    updated_at: datetime
    last_eva_at: datetime | None


class EvaThreadDetail(EvaThreadOut):
    requests: list[EvaRequestOut]


class EvaThreadQuery(PageQuery):
    state: ThreadState | None = None


class EvaWhitelistAdd(In):
    email: str = Field(min_length=3, max_length=254)
    name: str = Field("", max_length=160)


class EvaThreadUpdate(In):
    state: Literal["em_andamento", "concluido", "parado"]


# ---------------------------------------------------------------- conversa com a EVA
class EvaImageIn(In):
    name: str = Field("", max_length=120)
    content_type: Literal["image/png", "image/jpeg", "image/webp"]
    data: str = Field(min_length=8, max_length=7_000_000, description="Conteúdo da imagem em base64 (até 5 MB somando todas).")


class EvaConversationCreate(In):
    subject: str = Field(min_length=1, max_length=300)
    message: str = Field(min_length=1, max_length=20000, description="O pedido, como seria escrito no e-mail.")
    images: list[EvaImageIn] = Field(default_factory=list, max_length=4, description="Até 4 imagens (prints de tela, por exemplo).")
    cc: list[str] = Field(default_factory=list, max_length=10, description="Pessoas que também recebem a resposta por e-mail.")
    email_copy: bool = Field(True, description="true = além de ficar na API, a resposta sai pelo e-mail de sempre (para o responsável da chave e cc).")


class EvaMessageCreate(In):
    message: str = Field(min_length=1, max_length=20000, description="Continuação da conversa — inclusive a resposta a uma confirmação da EVA.")
    images: list[EvaImageIn] = Field(default_factory=list, max_length=4)
    cc: list[str] = Field(default_factory=list, max_length=10)
    email_copy: bool = True


class EvaConversationAccepted(Out):
    conversation_id: int
    request_id: int
    message_id: int
    status: Literal["queued"] = "queued"
    queue_position: int = Field(description="Posição na fila da EVA (1 = o próximo).")
    poll: str = Field(description="Onde acompanhar a resposta (long polling).")


class EvaAttachmentOut(Out):
    id: int
    name: str
    content_type: str
    size: int
    url: str = Field(description="Download autenticado (mesma chave).")


class EvaMessageOut(Out):
    id: int
    direction: Literal["in", "out"] = Field(description="in = enviada à EVA; out = resposta da EVA.")
    channel: Literal["email", "api"]
    author: str
    created_at: datetime
    subject: str
    text: str = Field(description="Texto da mensagem (na resposta da EVA, em texto simples).")
    html: str | None = Field(None, description="Resposta da EVA em HTML, idêntica ao e-mail.")
    status: str | None = Field(None, description="Resultado da resposta: publicado, sem_mudanca, nao_publicado, desfeito…")
    status_text: str | None = None
    reply: dict | None = Field(None, description="Resposta estruturada: saudacao, paragrafos, o_que_fiz, proximos_passos_*, fechamento…")
    request_id: int | None
    attachments: list[EvaAttachmentOut]


class EvaConversationDetail(EvaThreadOut):
    messages: list[EvaMessageOut]
    requests: list[EvaRequestOut]


class EvaMessagesQuery(Query):
    after: int = Field(0, ge=0, description="Só mensagens com id maior que este (o último que você já recebeu).")
    wait: int = Field(0, ge=0, le=25, description="Segundos para segurar a conexão esperando novidade (long polling, até 25).")
