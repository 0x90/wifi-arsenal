# -*- coding: iso-8859-1 -*-
"""
    Regulatory Database

    @copyright: 2008 Johannes Berg
    @license: ISC, see LICENSE for details.
"""

import codecs, math
from dbparse import DBParser, flag_definitions

Dependencies = ["time"]

def _country(macro, countries, code):
    result = []

    f = macro.formatter

    result.extend([
        f.heading(1, 1),
        f.text('Regulatory definition for %s' % _get_iso_code(code)),
        f.heading(0, 1),
    ])

    try:
        country = countries[code]
    except:
        result.append(f.text('No information available'))
        return ''.join(result)
    

    if country.comments:
        result.extend([
            f.preformatted(1),
            f.text('\n'.join(country.comments)),
            f.preformatted(0),
        ])

    result.append(f.table(1))
    result.extend([
        f.table_row(1),
          f.table_cell(1), f.strong(1),
            f.text('Band [MHz]'),
          f.strong(0), f.table_cell(0),
          f.table_cell(1), f.strong(1),
            f.text('Max BW [MHz]'),
          f.strong(0), f.table_cell(0),
          f.table_cell(1), f.strong(1),
            f.text('Flags'),
          f.strong(0), f.table_cell(0),
          f.table_cell(1), f.strong(1),
            f.text('Max antenna gain [dBi]'),
          f.strong(0), f.table_cell(0),
          f.table_cell(1), f.strong(1),
            f.text('Max EIRP [dBm'),
            f.hardspace,
            f.text('(mW)]'),
          f.strong(0), f.table_cell(0),
        f.table_row(0),
    ])

    for perm in country.permissions:
        def str_or_na(val, dBm=False):
            if val and not dBm:
                return '%.2f' % val
            elif val:
                return '%.2f (%.2f)' % (val, math.pow(10, val/10.0))
            return 'N/A'
        result.extend([
            f.table_row(1),
              f.table_cell(1),
                f.text('%.3f - %.3f' % (perm.freqband.start, perm.freqband.end)),
              f.table_cell(0),
              f.table_cell(1),
                f.text('%.3f' % (perm.freqband.maxbw,)),
              f.table_cell(0),
              f.table_cell(1),
                f.text(', '.join(perm.textflags)),
              f.table_cell(0),
              f.table_cell(1),
                f.text(str_or_na(perm.power.max_ant_gain)),
              f.table_cell(0),
              f.table_cell(1),
                f.text(str_or_na(perm.power.max_eirp, dBm=True)),
              f.table_cell(0),
            f.table_row(0),
        ])
    
    result.append(f.table(0))

    result.append(f.linebreak(0))
    result.append(f.linebreak(0))
    result.append(macro.request.page.link_to(macro.request, 'return to country list'))
    return ''.join(result)

_iso_list = {}

def _get_iso_code(code):
    if not _iso_list:
        for line in codecs.open('/usr/share/iso-codes/iso_3166.tab', encoding='utf-8'):
            line = line.strip()
            c, name = line.split('\t')
            _iso_list[c] = name
    return _iso_list.get(code, 'Unknown (%s)' % code)

def macro_Regulatory(macro):
    _ = macro.request.getText
    request = macro.request
    f = macro.formatter

    country = request.form.get('alpha2', [None])[0]

    dbpath = '/tmp/db.txt'
    if hasattr(request.cfg, 'regdb_path'):
        dbpath = request.cfg.regdb_path

    result = []

    if request.form.get('raw', [None])[0]:
        result.append(f.code_area(1, 'db-raw', show=1, start=1, step=1))
        for line in open(dbpath):
            result.extend([
                f.code_line(1),
                f.text(line.rstrip()),
                f.code_line(0),
            ])
        result.append(f.code_area(0, 'db-raw'))
        result.append(macro.request.page.link_to(macro.request, 'return to country list'))
        return ''.join(result)

    warnings = []
    countries = DBParser(warn=lambda x: warnings.append(x)).parse(open(dbpath))

    if country:
        return _country(macro, countries, country)

    countries = countries.keys()
    countries = [(_get_iso_code(code), code) for code in countries]
    countries.sort()

    result.extend([
        f.heading(1, 1),
        f.text('Countries'),
        f.heading(0, 1),
    ])

    result.append(f.bullet_list(1))
    for name, code in countries:
        result.extend([
          f.listitem(1),
          request.page.link_to(request, name, querystr={'alpha2': code}),
          f.listitem(0),
        ])
    result.append(f.bullet_list(0))

    if warnings:
        result.append(f.heading(1, 2))
        result.append(f.text("Warnings"))
        result.append(f.heading(0, 2))
        result.append(f.preformatted(1))
        result.extend(warnings)
        result.append(f.preformatted(0))

    result.append(request.page.link_to(request, 'view raw database', querystr={'raw': 1}))

    return ''.join(result)
