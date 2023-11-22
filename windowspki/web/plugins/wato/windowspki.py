#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

from cmk.gui.i18n import _
from cmk.gui.valuespec import (
    Dictionary,
    Tuple,
    Integer,
    ListOfStrings,
    MonitoringState,
    TextAscii,
    DropdownChoice,
)

from cmk.gui.plugins.wato import (
    rulespec_registry,
    CheckParameterRulespecWithItem,
    RulespecGroupCheckParametersApplications,
    HostRulespec,
)

def _item_spec_windowspki():
    return DropdownChoice(
        title = _("Windows PKI"),
        help = _("The plugin invenorize the certificates in a Windows PKI"),
        choices=[
            (True, _("Deploy plugin")),
            (False, _("Do not deploy")),
        ],
    )    

def _parameter_valuespec_windowspki():
    return Dictionary(
        elements = [
            ('age', Tuple(
                title = _('Certificate Age'),
                help = _("Days until expiry of certificate"),
                elements = [
                    Integer(title = _("Warning at"), unit = _("days"), default_value = 29),
                    Integer(title = _("Critical at"), unit = _("days"), default_value = 30),
                ])),
            ('ignore',
             Tuple(
                title = _('Ignore old Certificates'),
                help = _('Set number of days after which an expired certificate is ignored. A reason has to be given.'),
                elements = [
                    Integer(title = _('Ignore after'), unit = _('days'), default_value = 365),
                    TextAscii(title = _('Reason'), allow_empty = False, size = 72),
                ])),
        ],
    )

rulespec_registry.register(
    CheckParameterRulespecWithItem(
        check_group_name="windowspki",
        group=RulespecGroupCheckParametersApplications,
        item_spec=_item_spec_windowspki,
        match_type="dict",
        parameter_valuespec=_parameter_valuespec_windowspki,
        title=lambda: _("Parameters for Windows PKI SSL certificates"),
    ))

def _valuespec_windowspki_inventory():
    return Dictionary(
        title=_("Windows PKI SSL certificates discovery"),
        help=_("This selects which certificates are discovered."),
        elements=[
            ('min_lifetime',
             Age(
                 title=_("Minimal lifetime of certificate"),
                 default_value=864000,
                 help=_("Certificates with a lifetime less than this value will not be discovered."),
            )),
        ],
    )

rulespec_registry.register(
    HostRulespec(
        group=RulespecGroupCheckParametersDiscovery,
        name="windowspki_inventory",
        valuespec=_valuespec_windowspki_inventory,
    ))