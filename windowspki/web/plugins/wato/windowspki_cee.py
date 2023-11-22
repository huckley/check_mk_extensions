#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

try:
    from cmk.gui.i18n import _
    from cmk.gui.plugins.wato import (
        HostRulespec,
        rulespec_registry,
    )
    from cmk.gui.cee.plugins.wato.agent_bakery.rulespecs.utils import RulespecGroupMonitoringAgentsAgentPlugins
    from cmk.gui.valuespec import (
        Age,
        Alternative,
        Dictionary,
        FixedValue,
        ListOfStrings,
        TextAscii,
    )


    def _valuespec_agent_config_windowspki():
        return Alternative(
            title = _("Windows PKI SSL Certificates"),
            help = _("This will deploy the agent plugin <tt>windowspki</tt> "
                     "for checking SSL certificate files in a Windows PKI."),
            style = "dropdown",
            elements = [
                Dictionary(
                    title = _("Deploy the Windows PKI SSL certificates plugin"),
                    elements = [
                        ("interval", Age(
                            title = _("Run asynchronously"),
                            label = _("Interval for collecting data"),
                            default_value = 3600
                        )),
                    ],
                    optional_keys = ['interval'],
                ),
                FixedValue(None, title = _("Do not deploy the Windows PKI SSL certificates plugin"), totext = _("(disabled)") ),
            ]
        )

    rulespec_registry.register(
         HostRulespec(
             group=RulespecGroupMonitoringAgentsAgentPlugins,
             name="agent_config:windowspki",
             valuespec=_valuespec_agent_config_windowspki,
         ))

except ModuleNotFoundError:
    # RAW edition
    pass
