"""
red_team.mutators — concrete mutator implementations.

Each module in this package registers a Mutator instance with the global
registry on import. Adding a new mutator means: (1) write the module,
(2) import it here.
"""

from src.red_team.mutators import dead_code  # noqa: F401
from src.red_team.mutators import sink_attr_obfuscate  # noqa: F401
from src.red_team.mutators import sink_via_globals  # noqa: F401
from src.red_team.mutators import string_split  # noqa: F401
from src.red_team.mutators import taint_through_dict  # noqa: F401
from src.red_team.mutators import variable_rename  # noqa: F401
from src.red_team.mutators import wrapper_extraction  # noqa: F401
