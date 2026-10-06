"""The tier 3 detectors that the ``model`` evaluator runs.

A detector learns what is normal from the estate's own history and scores the
recent hours against it. It calls no model and it adds no dependency: the
first detectors stay pure Python by decision 3 of the four-tier design.

This package holds no import of its own. :mod:`soc_ai.hunting.spec` imports
the parameter models from :mod:`soc_ai.hunting.detectors.params`, and a
detector module imports the grid helpers. An import here would pull the grid
helpers into every spec parse.
"""
