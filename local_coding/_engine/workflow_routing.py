"""Task-purpose veto for product generation; no scheduler or provider routing."""
from workflow_core import ContractError, TASK_CATEGORIES


class TaskRoutingError(ContractError):
    def __init__(self, code, message):
        super().__init__(code + ': ' + message)
        self.routing_error_code = code


def require_product_category(packet, *, required=False):
    if not isinstance(packet, dict) or 'task_category' not in packet:
        if required:
            raise TaskRoutingError('TASK_CATEGORY_REQUIRED', 'Bind explicit product-development context.')
        return
    category = packet['task_category']
    if not isinstance(category, str) or category not in TASK_CATEGORIES:
        raise TaskRoutingError('TASK_CATEGORY_INVALID', 'Unknown declared category.')
    if category == 'unresolved':
        raise TaskRoutingError('TASK_CONTEXT_UNRESOLVED', 'Resolve task context before local generation.')
    if category == 'coding-test':
        raise TaskRoutingError('CODING_TEST_REQUIRES_CODEX_MAIN', 'Continue in the existing Codex task; no provider dispatch.')

