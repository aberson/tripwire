"""Synthetic git-repo fixtures for tripwire workspace-probe tests.

Builders construct frozen positive (bad) and negative (clean) workspace states
under a pytest ``tmp_path``, using only real ``git`` commands so the probes see
authentic repository state. See :mod:`fixtures.repos`.
"""
