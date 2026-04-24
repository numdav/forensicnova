"""ForensicNova dashboard — WTForms form definitions.

FlaskForm (from flask_wtf) automatically wires in the CSRF token as a
hidden field — rendered in the template via {{ form.hidden_tag() }}.
Validation happens on POST via form.validate_on_submit(), which returns
True only when:
  1. request.method == 'POST'
  2. CSRF token is valid
  3. All field-level validators pass
"""
from __future__ import annotations

from flask_wtf import FlaskForm
from wtforms import PasswordField, SelectField, StringField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(FlaskForm):
    """Keystone credentials form.

    Project name is NOT a form field — it is fixed to cfg.forensics_project
    on the server side, so the analyst never has to know the internal
    project layout.  Username + password are the only things the user sees.
    """

    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=1, max=64)],
        render_kw={"autocomplete": "username", "autofocus": True},
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=1, max=128)],
        render_kw={"autocomplete": "current-password"},
    )
    submit = SubmitField("Sign In")


class AcquireForm(FlaskForm):
    """Acquisition trigger form.

    The instance_id choices are populated dynamically by the view at GET
    time (not at class definition time) — the list of Nova instances is
    fetched from the API on each page load so it's always fresh.

    Non-ACTIVE VMs are included in the dropdown but disabled at the
    template level (via <option disabled>), so the operator sees the
    full cloud panorama and understands why a VM is not acquirable.
    """

    instance_id = SelectField(
        "Target VM",
        validators=[DataRequired()],
        choices=[],  # populated by view at request time
    )
    submit = SubmitField("Start acquisition")
