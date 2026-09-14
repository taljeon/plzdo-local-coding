"""Fixed fail-closed HN boundary; it never loads records or old allowances.

The inspected HN formalization contract is v1 and has no compatible v2 process
snapshot/marker protocol. Changing HN is outside this candidate's authority.
"""


class HNBackendUnsupported(RuntimeError):
    code = 'HN_BACKEND_PROTOCOL_UNSUPPORTED'


def verify_parent_snapshot(*args, **kwargs):
    raise HNBackendUnsupported(
        'The installed private HN contract has no compatible v2 read-only snapshot protocol; '
        'use a new standalone private approval or the fixed PlzDo parent backend')
