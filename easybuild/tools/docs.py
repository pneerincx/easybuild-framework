# #
# Copyright 2009-2015 Ghent University
#
# This file is part of EasyBuild,
# originally created by the HPC team of Ghent University (http://ugent.be/hpc/en),
# with support of Ghent University (http://ugent.be/hpc),
# the Flemish Supercomputer Centre (VSC) (https://vscentrum.be/nl/en),
# the Hercules foundation (http://www.herculesstichting.be/in_English)
# and the Department of Economy, Science and Innovation (EWI) (http://www.ewi-vlaanderen.be/en).
#
# http://github.com/hpcugent/easybuild
#
# EasyBuild is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation v2.
#
# EasyBuild is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with EasyBuild.  If not, see <http://www.gnu.org/licenses/>.
# #
"""
Documentation-related functionality

@author: Stijn De Weirdt (Ghent University)
@author: Dries Verdegem (Ghent University)
@author: Kenneth Hoste (Ghent University)
@author: Pieter De Baets (Ghent University)
@author: Jens Timmerman (Ghent University)
@author: Toon Willems (Ghent University)
@author: Ward Poelmans (Ghent University)
"""
import copy
import inspect
import os

from easybuild.framework.easyconfig.default import DEFAULT_CONFIG, HIDDEN, sorted_categories
from easybuild.framework.easyconfig.easyconfig import get_easyblock_class
from easybuild.tools.filetools import read_file
from easybuild.tools.ordereddict import OrderedDict
from easybuild.tools.toolchain.utilities import search_toolchain
from easybuild.tools.utilities import import_available_modules, quote_str
from vsc.utils.missing import nub


FORMAT_RST = 'rst'
FORMAT_TXT = 'txt'


def det_col_width(entries, title):
    """Determine column width based on column title and list of entries."""
    return max(map(len, entries + [title]))


def avail_easyconfig_params_rst(title, grouped_params):
    """
    Compose overview of available easyconfig parameters, in RST format.
    """
    # main title
    lines = [
        title,
        '=' * len(title),
        '',
    ]

    for grpname in grouped_params:
        # group section title
        lines.append("%s parameters" % grpname)
        lines.extend(['-' * len(lines[-1]), ''])

        titles = ["**Parameter name**", "**Description**", "**Default value**"]
        values = [
            ['``' + name + '``' for name in grouped_params[grpname].keys()],  # parameter name
            [x[0] for x in grouped_params[grpname].values()],  # description
            [str(quote_str(x[1])) for x in grouped_params[grpname].values()]  # default value
        ]

        lines.extend(mk_rst_table(titles, values))
        lines.append('')

    return '\n'.join(lines)


def avail_easyconfig_params_txt(title, grouped_params):
    """
    Compose overview of available easyconfig parameters, in plain text format.
    """
    # main title
    lines = [
        '%s:' % title,
        '',
    ]

    for grpname in grouped_params:
        # group section title
        lines.append(grpname.upper())
        lines.append('-' * len(lines[-1]))

        # determine width of 'name' column, to left-align descriptions
        nw = max(map(len, grouped_params[grpname].keys()))

        # line by parameter
        for name, (descr, dflt) in sorted(grouped_params[grpname].items()):
            lines.append("{0:<{nw}}   {1:} [default: {2:}]".format(name, descr, str(quote_str(dflt)), nw=nw))
        lines.append('')

    return '\n'.join(lines)


def avail_easyconfig_params(easyblock, output_format):
    """
    Compose overview of available easyconfig parameters, in specified format.
    """
    params = copy.deepcopy(DEFAULT_CONFIG)

    # include list of extra parameters (if any)
    extra_params = {}
    app = get_easyblock_class(easyblock, default_fallback=False)
    if app is not None:
        extra_params = app.extra_options()
    params.update(extra_params)

    # compose title
    title = "Available easyconfig parameters"
    if extra_params:
        title += " (* indicates specific to the %s easyblock)" % app.__name__

    # group parameters by category
    grouped_params = OrderedDict()
    for category in sorted_categories():
        # exclude hidden parameters
        if category[1].upper() in [HIDDEN]:
            continue

        grpname = category[1]
        grouped_params[grpname] = {}
        for name, (dflt, descr, cat) in params.items():
            if cat == category:
                if name in extra_params:
                    # mark easyblock-specific parameters
                    name = '%s*' % name
                grouped_params[grpname].update({name: (descr, dflt)})

        if not grouped_params[grpname]:
            del grouped_params[grpname]

    # compose output, according to specified format (txt, rst, ...)
    avail_easyconfig_params_functions = {
        FORMAT_RST: avail_easyconfig_params_rst,
        FORMAT_TXT: avail_easyconfig_params_txt,
    }
    return avail_easyconfig_params_functions[output_format](title, grouped_params)

def list_toolchains(output_format=FORMAT_TXT):
    """Show list of known toolchains."""
    _, all_tcs = search_toolchain('')
    all_tcs_names = [x.NAME for x in all_tcs]
    tclist = sorted(zip(all_tcs_names, all_tcs))

    tcs = dict()
    for (tcname, tcc) in tclist:
        tc = tcc(version='1.2.3')  # version doesn't matter here, but something needs to be there
        tcs[tcname] = tc.definition()

    list_toolchains_functions = {
        FORMAT_RST: list_toolchains_rst,
        FORMAT_TXT: list_toolchains_txt,
    }

    return list_toolchains_functions[output_format](tcs)

def list_toolchains_rst(tcs):
    """ Returns overview of all toolchains in rst format """
    txt = []
    title = "List of known toolchains"
    txt.extend([title, "=" * len(title), ''])

    # figure out column names
    column_heads = ["NAME", "COMPILER", "MPI"]
    for d in tcs.values():
        column_heads.extend(d.keys())

    column_heads = nub(column_heads)

    values = [[] for i in range(len(column_heads))]
    values[0] = tcs.keys()

    for i in range(len(column_heads)-1):
        for d in tcs.values():
            values[i+1].append(', '.join(d.get(column_heads[i+1], [])))

    txt.extend(mk_rst_table(column_heads, values))

    return '\n'.join(txt)

def list_toolchains_txt(tcs):
    """ Returns overview of all toolchains in txt format """
    txt = ["List of known toolchains (toolchainname: module[,module...]):"]
    for name in sorted(tcs):
        tc_elems = nub(sorted([e for es in tcs[name].values() for e in es]))
        txt.append("\t%s: %s" % (name, ', '.join(tc_elems)))

    return '\n'.join(txt)

def gen_easyblocks_overview_rst(package_name, path_to_examples, common_params={}, doc_functions=[]):
    """
    Compose overview of all easyblocks in the given package in rst format
    """
    modules = import_available_modules(package_name)
    docs = []
    all_blocks = []

    # get all blocks
    for mod in modules:
        for name,obj in inspect.getmembers(mod, inspect.isclass):
            eb_class = getattr(mod, name)
            # skip imported classes that are not easyblocks
            if eb_class.__module__.startswith(package_name) and eb_class not in all_blocks:
                all_blocks.append(eb_class)

    for eb_class in sorted(all_blocks, key=lambda c: c.__name__):
        docs.append(gen_easyblock_doc_section_rst(eb_class, path_to_examples, common_params, doc_functions, all_blocks))

    title = 'Overview of generic easyblocks'

    heading = [
        '*(this page was generated automatically using* ``easybuild.tools.docs.gen_easyblocks_overview_rst()`` *)*',
        '',
        '=' * len(title),
        title,
        '=' * len(title),
        '',
    ]

    contents = [":ref:`" + b.__name__ + "`" for b in sorted(all_blocks, key=lambda b: b.__name__)]
    toc = ' - '.join(contents)
    heading.append(toc)
    heading.append('')

    return heading + docs


def gen_easyblock_doc_section_rst(eb_class, path_to_examples, common_params, doc_functions, all_blocks):
    """
    Compose overview of one easyblock given class object of the easyblock in rst format
    """
    classname = eb_class.__name__

    lines = [
        '.. _' + classname + ':',
        '',
        '``' + classname + '``',
        '=' * (len(classname)+4),
        '',
    ]

    bases = []
    for b in eb_class.__bases__:
        base = ':ref:`' + b.__name__ +'`' if b in all_blocks else b.__name__
        bases.append(base)

    derived = '(derives from ' + ', '.join(bases) + ')'
    lines.extend([derived, ''])

    # Description (docstring)
    lines.extend([eb_class.__doc__.strip(), ''])

    # Add extra options, if any
    if eb_class.extra_options():
        extra_parameters = 'Extra easyconfig parameters specific to ``' + classname + '`` easyblock'
        lines.extend([extra_parameters, '-' * len(extra_parameters), ''])
        ex_opt = eb_class.extra_options()

        titles = ['easyconfig parameter', 'description', 'default value']
        values = [
            ['``' + key + '``' for key in ex_opt],  # parameter name
            [val[1] for val in ex_opt.values()],  # description
            ['``' + str(quote_str(val[0])) + '``' for val in ex_opt.values()]  # default value
        ]

        lines.extend(mk_rst_table(titles, values))

    # Add commonly used parameters
    if classname in common_params:
        commonly_used = 'Commonly used easyconfig parameters with ``' + classname + '`` easyblock'
        lines.extend([commonly_used, '-' * len(commonly_used)])

        titles = ['easyconfig parameter', 'description']
        values = [
            [opt for opt in common_params[classname]],
            [DEFAULT_CONFIG[opt][1] for opt in common_params[classname]],
        ]

        lines.extend(mk_rst_table(titles, values))

        lines.append('')

    # Add docstring for custom steps
    custom = []
    inh = ''
    f = None
    for func in doc_functions:
        if func in eb_class.__dict__:
            f = eb_class.__dict__[func]

        if f.__doc__:
            custom.append('* ``' + func + '`` - ' + f.__doc__.strip() + inh)

    if custom:
        title = 'Customised steps in ``' + classname + '`` easyblock'
        lines.extend([title, '-' * len(title)] + custom)
        lines.append('')

    # Add example if available
    if os.path.exists(os.path.join(path_to_examples, '%s.eb' % classname)):
        title = 'Example for ``' + classname + '`` easyblock'
        lines.extend(['', title, '-' * len(title), '', '::', ''])
        for line in read_file(os.path.join(path_to_examples, classname+'.eb')).split('\n'):
            lines.append('    ' + line.strip())
        lines.append('') # empty line after literal block

    return '\n'.join(lines)


def mk_rst_table(titles, values):
    """
    Returns an rst table with given titles and values (a nested list of string values for each column)
    """
    num_col = len(titles)
    table = []
    col_widths = []
    tmpl = []
    line= []

    # figure out column widths
    for i in range(0, num_col):
        col_widths.append(det_col_width(values[i], titles[i]))

        # make line template
        tmpl.append('{' + str(i) + ':{c}<' + str(col_widths[i]) + '}')
        line.append('') # needed for table line

    line_tmpl = '   '.join(tmpl)
    table_line = line_tmpl.format(*line, c="=")

    table.append(table_line)
    table.append(line_tmpl.format(*titles, c=' '))
    table.append(table_line)

    for i in range(0, len(values[0])):
        table.append(line_tmpl.format(*[v[i] for v in values], c=' '))

    table.extend([table_line, ''])

    return table
