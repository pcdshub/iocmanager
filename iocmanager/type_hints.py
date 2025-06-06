"""
The type_hints module defines some commonly-used type annotations.

These should be re-usable in multiple submodules.
"""

from qtpy.QtWidgets import QWidget

ParentWidget = QWidget | None
