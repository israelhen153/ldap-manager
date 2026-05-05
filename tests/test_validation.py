"""Tests for input validation."""

import click
import pytest

from ldap_manager.validation import validate_uid


class TestValidateUid:
    """Exercises every rejection path and boundary condition."""

    # ── Valid inputs ──
    def test_simple(self):
        assert validate_uid("jdoe") == "jdoe"

    def test_dots(self):
        assert validate_uid("j.doe") == "j.doe"

    def test_dashes(self):
        assert validate_uid("j-doe") == "j-doe"

    def test_underscores(self):
        assert validate_uid("j_doe") == "j_doe"

    def test_mixed(self):
        assert validate_uid("john.doe-123_test") == "john.doe-123_test"

    def test_single_letter(self):
        assert validate_uid("a") == "a"

    def test_max_length(self):
        uid = "a" * 256
        assert validate_uid(uid) == uid

    # ── Rejections — format ──
    def test_reject_empty(self):
        with pytest.raises(click.ClickException, match="Invalid UID"):
            validate_uid("")

    def test_reject_spaces(self):
        with pytest.raises(click.ClickException, match="Invalid UID"):
            validate_uid("has spaces")

    def test_reject_leading_digit(self):
        with pytest.raises(click.ClickException, match="Invalid UID"):
            validate_uid("123user")

    def test_reject_leading_dash(self):
        with pytest.raises(click.ClickException, match="Invalid UID"):
            validate_uid("-user")

    def test_reject_leading_dot(self):
        with pytest.raises(click.ClickException, match="Invalid UID"):
            validate_uid(".user")

    # ── Rejections — security ──
    def test_reject_null_byte(self):
        with pytest.raises(click.ClickException, match="Invalid UID"):
            validate_uid("user\x00null")

    def test_reject_comma(self):
        with pytest.raises(click.ClickException, match="Invalid UID"):
            validate_uid("admin,dc=evil")

    def test_reject_semicolon(self):
        with pytest.raises(click.ClickException, match="Invalid UID"):
            validate_uid("user;drop")

    def test_reject_equals(self):
        with pytest.raises(click.ClickException, match="Invalid UID"):
            validate_uid("uid=admin")

    def test_reject_backslash(self):
        with pytest.raises(click.ClickException, match="Invalid UID"):
            validate_uid("user\\test")

    def test_reject_plus(self):
        with pytest.raises(click.ClickException, match="Invalid UID"):
            validate_uid("user+test")

    def test_reject_quotes(self):
        with pytest.raises(click.ClickException, match="Invalid UID"):
            validate_uid('user"test')

    def test_reject_angle_brackets(self):
        with pytest.raises(click.ClickException, match="Invalid UID"):
            validate_uid("user<test>")

    # ── Rejections — length ──
    def test_reject_too_long(self):
        with pytest.raises(click.ClickException, match="too long"):
            validate_uid("a" * 257)
