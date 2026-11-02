# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate a role's argument_specs.yml, defaults, resolver and guards from meta/argument_specs.py.

Public surface: the pydantic models a role's argument_specs.py builds, and the `argspec` CLI
(`ansible_devkit.argspec.cli`).
"""

from ansible_devkit.argspec.models import (
    REGENERATE_COMMAND,
    ArgumentSpec,
    ArgumentSpecs,
    OptionSpec,
)

__all__ = ["REGENERATE_COMMAND", "ArgumentSpec", "ArgumentSpecs", "OptionSpec"]
