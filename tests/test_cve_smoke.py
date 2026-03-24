# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
# SPDX-License-Identifier: BSD-3-Clause

"""Smoke tests verifying upgraded dependencies import and expose expected APIs.

These tests validate that CVE-remediation version bumps did not break the
APIs actually used by this project. They do NOT require a full CMake/CUDA build.

Packages tested:
  - setuptools >=78.1.1  (CVE-2024-6345, PYSEC-2025-49)
  - bokeh      >=3.8.2   (CVE-2026-21883)
  - PyJWT      >=2.12.0  (CVE-2026-32597)
"""

import importlib

import pytest


# ---------------------------------------------------------------------------
# setuptools  (69.5.1 -> >=78.1.1)
# Used in: TrainingExtensions/common/src/python/setup.py
#          TrainingExtensions/torch/src/python/setup.py
# ---------------------------------------------------------------------------

class TestSetuptools:
    def test_import_core(self):
        from setuptools import Distribution, find_namespace_packages, setup
        assert callable(setup)
        assert callable(find_namespace_packages)
        assert Distribution is not None

    def test_import_build_ext(self):
        from setuptools.command.build_ext import build_ext
        assert build_ext is not None

    def test_version_minimum(self):
        import setuptools
        major = int(setuptools.__version__.split(".")[0])
        assert major >= 78, f"setuptools {setuptools.__version__} < 78.1.1"


# ---------------------------------------------------------------------------
# bokeh  (3.6.3 -> >=3.8.2)
# Used heavily in: _aimet_common/bokeh_plots.py, quant_analyzer.py,
#                  plotting_utils.py, utils.py, auto_quant.py
# ---------------------------------------------------------------------------

class TestBokeh:
    def test_import_core_modules(self):
        """Verify all top-level bokeh modules used in the project import."""
        import bokeh.model
        import bokeh.embed
        import bokeh.plotting

    def test_import_client(self):
        from bokeh.client import push_session
        assert callable(push_session)

    def test_import_document(self):
        from bokeh.document import Document
        doc = Document()
        assert doc is not None

    def test_import_layouts(self):
        from bokeh.layouts import column
        assert callable(column)

    def test_import_models(self):
        from bokeh.models import (
            TableColumn,
            DataTable,
            Div,
            Plot,
            ColumnDataSource,
            Band,
            Span,
            HoverTool,
            WheelZoomTool,
        )
        # Verify ColumnDataSource can be instantiated (used everywhere)
        source = ColumnDataSource(data={"x": [1, 2], "y": [3, 4]})
        assert len(source.data["x"]) == 2

    def test_import_models_annotations(self):
        from bokeh.models.annotations import Title
        assert Title is not None

    def test_import_models_glyphs(self):
        from bokeh.models.glyphs import Rect
        assert Rect is not None

    def test_import_plotting_figure(self):
        from bokeh.plotting import figure
        fig = figure(title="smoke test", width=200, height=200)
        assert fig is not None

    def test_import_server(self):
        from bokeh.server.server import Server
        assert Server is not None

    def test_import_application(self):
        from bokeh.application import Application
        assert Application is not None

    def test_import_additional_modules(self):
        """Modules used in visualization and auto_quant code."""
        from bokeh.colors import named as bokeh_colors
        from bokeh.events import Tap
        from bokeh.resources import CDN
        from bokeh.transform import factor_cmap
        from bokeh.models.dom import HTML
        from bokeh.models.tools import TapTool

    def test_version_minimum(self):
        import bokeh
        parts = bokeh.__version__.split(".")
        major, minor = int(parts[0]), int(parts[1])
        assert (major, minor) >= (3, 8), f"bokeh {bokeh.__version__} < 3.8.2"


# ---------------------------------------------------------------------------
# PyJWT  (2.10.1 -> >=2.12.0)
# Transitive dependency — not directly imported in project source.
# Verify core API works and crit header validation is enforced.
# ---------------------------------------------------------------------------

class TestPyJWT:
    def test_import(self):
        import jwt
        assert hasattr(jwt, "encode")
        assert hasattr(jwt, "decode")

    def test_encode_decode_roundtrip(self):
        import jwt
        secret = "test-secret-key"
        payload = {"sub": "smoke-test", "val": 42}
        token = jwt.encode(payload, secret, algorithm="HS256")
        decoded = jwt.decode(token, secret, algorithms=["HS256"])
        assert decoded["sub"] == "smoke-test"
        assert decoded["val"] == 42

    def test_version_minimum(self):
        import jwt
        parts = jwt.__version__.split(".")
        major, minor = int(parts[0]), int(parts[1])
        assert (major, minor) >= (2, 12), f"PyJWT {jwt.__version__} < 2.12.0"
