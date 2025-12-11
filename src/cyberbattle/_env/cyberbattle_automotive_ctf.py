# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

from ..samples.toyctf import automotive_ctf
from . import cyberbattle_env


class CyberBattleAutomotiveCTF(cyberbattle_env.CyberBattleEnv):
    """CyberBattle simulation based on a automotive CTF exercise"""

    def __init__(self, **kwargs):
        super().__init__(initial_environment=automotive_ctf.new_environment(), **kwargs)
