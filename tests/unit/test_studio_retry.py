"""Falhas passageiras do provedor de IA voltam o pedido do Estúdio para a fila; as definitivas não."""
from app.engine import studio


def test_transitorias():
    for e in ("serviço de IA indisponível (HTTP 504)", "falha de conexão com o serviço de IA: x", "resposta vazia",
              "resposta cortada pelo limite de tamanho", "serviço de IA interrompeu a resposta: y"):
        assert studio.TRANSIENT.search(e)
    for e in ("Teto de gasto de IA atingido (AI_BUDGET_USD).", "IA não configurada neste servidor.",
              "serviço de IA recusou a chamada (HTTP 400): z"):
        assert not studio.TRANSIENT.search(e)
