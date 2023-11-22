#!/usr/bin/env python3
# -*- encoding: utf-8; py-indent-offset: 4 -*-

# (c) 2020 Heinlein Support GmbH
#          Robert Sander <r.sander@heinlein-support.de>
# (c) 2023 Falk Hackenberger <code@huckley.de>

# This is free software;  you can redistribute it and/or modify it
# under the  terms of the  GNU General Public License  as published by
# the Free Software Foundation in version 2.  This file is distributed
# in the hope that it will be useful, but WITHOUT ANY WARRANTY;  with-
# out even the implied warranty of  MERCHANTABILITY  or  FITNESS FOR A
# PARTICULAR PURPOSE. See the  GNU General Public License for more de-
# ails.  You should have  received  a copy of the  GNU  General Public
# License along with GNU Make; see the file  COPYING.  If  not,  write
# to the Free Software Foundation, Inc., 51 Franklin St,  Fifth Floor,
# Boston, MA 02110-1301 USA.

from .agent_based_api.v1 import register, render, Result, Metric, State, check_levels, ServiceLabel, Service
import time
import json

def parse_windowspki(string_table):
    section = {}
    for line in string_table:
        if line[0][0] == '{':
            # new json format for section
            name = False
            data = json.loads(line[0])
            
            if 'serial' in data:
                name = data['serial']
            if name and 'subj' in data and 'expires' in data:
                section[name] = data
        else:
            name = line[0]
            section[name] = {
                'expires': int(line[1])
            }
            algosign = '/'
            if len(line) > 2:
                algosign = line[2]
            if algosign[0] == '/':
                # old agent plugin
                algosign = ''
                subjparts = line[2:]
            else:
                subjparts = line[3:]
            if subjparts[0].startswith('serial='):
                serial = subjparts[0][12:]
                subjparts = subjparts[1:]
            else:
                serial = None
            subject = " ".join(subjparts)

            section[name]['subj'] = subject
    return section

register.agent_section(
    name="windowspki",
    parse_function=parse_windowspki,
)

def discover_windowspki(params, section):
    for name, data in section.items():
        if 'min_lifetime' in params and 'starts' in data:
            if data['expires'] - data['starts'] < params['min_lifetime']:
                continue
        sl = []
        if data.get('serial'):
            sl.append(ServiceLabel(u'windowspki/serial', data['serial']))
        yield Service(item=name, labels=sl)

def check_windowspki(item, params, section):
    warn, crit = params.get('age', (0, 0))
    ignore = params.get('ignore', None)

    if item in section:
        data = section[item]
        
        now = int(time.time())
        secondsremaining = data['expires'] - now
        ignored = False

        yield Result(state=State.OK, summary="Subject: %s" % data['subj'])

        if secondsremaining < 0:
            infotext = "expired %s ago on %s" % ( render.timespan(abs(secondsremaining)),
                                                  time.strftime("%c", time.gmtime(data['expires'])))
        else:
            infotext = "expires in %s on %s" % ( render.timespan(secondsremaining),
                                                 time.strftime("%c", time.gmtime(data['expires'])))
        if ignore and -secondsremaining > ignore[0] * 86400:
            yield Result(state=State.OK, summary=infotext + ', ignored because "%s"' % ignore[1])
            ignored = True
        else:
            if secondsremaining > 0:
                yield from check_levels(secondsremaining,
                    levels_lower=(warn * 86400, crit * 86400),
                    metric_name='lifetime_remaining',
                    label='Lifetime Remaining',
                    render_func=render.timespan,
                    )
            else:
                yield from check_levels(secondsremaining,
                    levels_lower=(warn * 86400, crit * 86400),
                    metric_name='lifetime_remaining',
                    label='Expired',
                    render_func=lambda x: "%s ago" % render.timespan(abs(x)),
                    )


register.check_plugin(
    name="windowspki",
    service_name="Windows PKI SSL Certificate in %s",
    sections=["windowspki"],
    discovery_function=discover_windowspki,
    discovery_default_parameters={},
    discovery_ruleset_name="windowspki_inventory",
    discovery_ruleset_type=register.RuleSetType.MERGED,
    check_function=check_windowspki,
    check_default_parameters={
        'age': ( 29, 21 ),
    },
    check_ruleset_name="windowspki",
)
