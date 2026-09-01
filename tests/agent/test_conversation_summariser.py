from backend.agent.conversation_summariser import ConversationSummariser
from backend import config


def test_conversation_summariser_instantiates_without_raising():
    """Regression: ConversationSummariser() raised AttributeError before config.settings
    gained summariser_threshold (RESEARCH.md Pitfall 1)."""
    summariser = ConversationSummariser()
    assert summariser.threshold == config.settings.summariser_threshold
    assert summariser.threshold == 60000
