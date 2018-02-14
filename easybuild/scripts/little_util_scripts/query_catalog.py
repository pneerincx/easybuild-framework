#!/usr/bin/env python
from __future__ import print_function
import argparse
import json
import logging
import os
import subprocess
import sys

major, minor, micro, releaselevel, serial = sys.version_info
if (major, minor) < (2, 7):
    print("CRITICAL: This script requires Python version >= 2.7.x")
    sys.exit(1)


#
# This program queries a catalog in JSON format of all software installed by EasyBuild.
# The catalog must be created with create_catalog.py before you can use this script.
#

class SmartFormatter(argparse.ArgumentDefaultsHelpFormatter):
    def _split_lines(self, text, width):
        # this is the RawTextHelpFormatter._split_lines
        if text.startswith('R|'):
            return text[2:].splitlines()
        return argparse.ArgumentDefaultsHelpFormatter._split_lines(self, text, width)


def main():
    #
    # Get defaults from ENV.
    #
    if 'EASYBUILD_CATALOG' in os.environ:
        easybuild_catalog = os.environ['EASYBUILD_CATALOG']
    else:
        if 'EASYBUILD_SUBDIR_SOFTWARE' in os.environ:
            easybuild_subdir_software = os.environ['EASYBUILD_SUBDIR_SOFTWARE']
        else:
            easybuild_subdir_software = 'software'  # default
        if 'EASYBUILD_INSTALLPATH' in os.environ:
            easybuild_catalog = os.environ['EASYBUILD_INSTALLPATH'] + '/' \
                              + easybuild_subdir_software + '/' \
                              + 'installed_with_easybuild.catalog'
        else:
            easybuild_catalog = None
    #
    # Get commandline options.
    #
    parser = argparse.ArgumentParser(
        description='Queries a catalog of software installed by EasyBuild.',
        # formatter_class=argparse.ArgumentDefaultsHelpFormatter
        formatter_class=SmartFormatter
    )
    parser.add_argument('-c', '--catalog',
                        help='Catalog flatfile '
                             'which contains a list of installed software modules. '
                             'You may create a catalog file using the create_catalog.py script.',
                        default=easybuild_catalog)
    parser.add_argument('-a', '--app',
                        help='Optionally restrict query to specified Application.'
                        'Must be specified in module syntax: either only app_name or '
                        'app_name/app_version.',
                        default=None)
    parser.add_argument('-t', '--tc',
                        help='Optionally restrict query to specified Tool Chain.'
                        'When specified must be in module syntax: either only tc_name or '
                        'tc_name/tc_version.',
                        default=None)
    output_group = parser.add_mutually_exclusive_group()
    output_group.add_argument('-d', '--deps',
                              help='List dependent software. '
                              'Hence modules depending on the one specified.',
                              action='store_true',
                              default=False)
    output_group.add_argument('-r', '--reqs',
                              help='List required software excluding toolchains. '
                              'Hence modules required for the one specified.',
                              action='store_true',
                              default=False)
    output_group.add_argument('-R', '--Reqs',
                              help='List required software including toolchains. '
                              'Like -r/--reqs, but consider an application\'s toolchain '
                              'also as a (special kind of) requirement.',
                              action='store_true',
                              default=False)
    parser.add_argument('-v', '--versions',
                        help='Must be either "all" or "newest" (default) '
                        'to report either all versions or only the newest version '
                        'of installed EasyConfigs.',
                        default='all')
    parser.add_argument('-p', '--paths',
                        help='List full path to EasyConfig files. '
                        'Default is to print only name/version '
                        'of the installed EasyConfigs in module syntax ',
                        action='store_true',
                        default=False)
    parser.add_argument('-l', '--loglevel',
                        help='Log level. One of DEBUG, INFO, WARNING, ERROR or CRITICAL.',
                        default='INFO')
    #
    # ToDo: implement the options below...
    #
#     parser.add_argument('-s', '--sub_tc_file',
#                         help='R|Optional file listing sub-toolchains '
#                         'in which to chase dependencies.\n'
#                         'Format should be:\n'
#                         'toolchain_name_1/toolchain_version_1\n'
#                         'toolchain_name_2/toolchain_version_2\n'
#                         'toolchain_name_3/toolchain_version_3\n'
#                         '...\n'
#                         'No effort is made to check for hierarchical '
#                         'relationships between toolchains.')
#     output_group.add_argument("-U", "--updates",
#                               help="Suggest updates for dependencies "
#                               "when a newer version is already installed."
#                               "Toolchain updates are not suggested.",
#                               action="store_true", default=False)
#     parser.add_argument('-m', '--messages',
#                         help='Create (Lmod admin) Messages file. '
#                              'Will print extra messages when a module is loaded with Lmod.'
#                              'Can be used to warn users that a module is deprecated '
#                              'and scheduled for removal',
#                         action='store_true',
#                         default=False)

    args = parser.parse_args()
    #
    # Configure logging.
    #
    loglevel = args.loglevel
    numeric_level = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError('CRITICAL: Invalid log level: %s' % loglevel)
    logging.basicConfig(stream=sys.stdout,
                        # level=logging.INFO,
                        # format='%(levelname)s:: %(filename)s:%(lineno)s %(message)s',
                        level=numeric_level,
                        format='%(levelname)+8s:: %(filename)s:%(lineno)d %(message)s')
    logging.info('Started...')
    #
    # Get catalog.
    #
    catalog_file = args.catalog
    if isinstance(catalog_file, str) and os.path.isfile(catalog_file):
        logging.info('Querying EasyBuild installed software catalog ' + catalog_file + '...')
    else:
        logging.critical('Please provide the path to the catalog file using either '
                         'the EASYBUILD_CATALOG environment variable or'
                         'the -c/--catalog command line argument.')
        sys.exit(2)
    #
    # Get query app and/or toolchain and optional app version + toolchain version.
    #
    if isinstance(args.app, str):
        q_app_string = args.app
        q_app = q_app_string.split('/', 1)
        q_app_name = q_app[0]
        if q_app_name == 'any':
            logging.debug('Will list all applications listed in the catalog.')
        else:
            logging.debug('Will query catalog for application named: ' + q_app_name)
        if len(q_app) == 2:
            q_app_vers = q_app[1]
            logging.debug('Will query catalog for application version: ' + q_app_vers)
        else:
            q_app_vers = None
            logging.debug('No application version specified.')
    else:
        q_app_name = None
        q_app_vers = None
        logging.debug('No app specified.')
    if isinstance(args.tc, str):
        q_tc_string = args.tc
        q_tc = q_tc_string.split('/', 1)
        q_tc_name = q_tc[0]
        logging.debug('Will query catalog for toolchain named: ' + q_tc_name)
        if len(q_tc) == 2:
            q_tc_vers = q_tc[1]
            logging.debug('Will query catalog for toolchain version: ' + q_tc_vers)
        else:
            q_tc_vers = None
            logging.debug('No toolchain version specified.')
    else:
        q_tc_name = None
        q_tc_vers = None
        logging.debug('No toolchain specified.')
    if q_app_name is None and q_tc_name is None:
        logging.critical('Must provide at least an application or toolchain '
                         'to query the catalog with -a/--app or -t/--tc.')
        logging.critical('You may use "--app any" to list all applications.')
        logging.critical('Use -h/--help to get a list of available commandline options '
                         'to do something useful with the app(s) or toolchain(s) found.')
        sys.exit(2)
    #
    # Get requested actions.
    #
    if isinstance(args.deps, bool):
        list_deps = args.deps
    if isinstance(args.reqs, bool):
        list_reqs_excl_toolchains = args.reqs
    if isinstance(args.Reqs, bool):
        list_reqs_incl_toolchains = args.Reqs
    if(args.versions == 'all'):
        list_old_versions = True
    elif(args.versions == 'newest'):
        list_old_versions = False
    else:
        logging.critical('--versions must be either "all" or "newest", '
                         'but found: ' + args.versions + '.')
        sys.exit(1)
    if isinstance(args.paths, bool):
        global list_paths
        list_paths = args.paths
    #
    # Determine term dimensions for pretty printing.
    #
    term_width = int(subprocess.check_output(['tput', 'cols']).decode())
    separator = '=' * term_width
    #
    # Parse the catalog file.
    # We are a bit greedy: slurp all lines into memory...
    #
    dep_level = 0
    try:
        catalog_fh = open(catalog_file, "r")
    except IOError:
        logging.critical('Cannot open catalog file ' + catalog_file)
        logging.critical('Check that the file exits and is readable.')
        sys.exit()
    catalog = json.loads(catalog_fh.read())
    catalog_fh.close()
    for app in catalog:
        logging.debug('Processing app ' + app['app_name'] + '...')
        if (q_app_name is None
                and (app['app_name'] == q_tc_name)
                and (app['app_vers'] == q_tc_vers or q_tc_vers is None)):
            #
            # Application matches query toolchain.
            #
            logging.debug('App ' + app['app_name'] + ' matches query terms.')
            print("{0}".format(separator))
            format_and_print(dep_level, app)
            if list_deps:
                get_needy_dependants(dep_level, catalog, app, True)
        if ((app['app_name'] == q_app_name or q_app_name == 'any')
                and (app['app_vers'] == q_app_vers or q_app_vers is None)
                and (app['tc_name'] == q_tc_name or q_tc_name is None)
                and (app['tc_vers'] == q_tc_vers or q_tc_vers is None)):
            #
            # Application matches query app.
            #
            logging.debug('App ' + app['app_name'] + ' matches query terms.')
            print("{0}".format(separator))
            format_and_print(dep_level, app)
            if list_deps:
                get_needy_dependants(dep_level, catalog, app, False)
            elif list_reqs_excl_toolchains:
                get_requirements(dep_level, catalog, app, False)
            elif list_reqs_incl_toolchains:
                get_requirements(dep_level, catalog, app, True)


def format_and_print(dep_level, app):
    #
    # Format.
    #
    indent = '\t' * dep_level
    ml_app_string = app['app_name'] + '/' + app['app_vers']
    if (app['tc_name'] != 'dummy'):
        ml_app_string += '-' + app['tc_name'] + '-' + app['tc_vers']
    if (app['app_vers_suffix'] != ''):
        ml_app_string += app['app_vers_suffix']
    if list_paths:
        formatted_line = "{0}: {1}{2}".format(
            dep_level, indent, app['easyconfig'])
    else:
        formatted_line = "{0}: {1}{2}".format(
            dep_level, indent, ml_app_string)
    #
    # Print.
    #
    print(formatted_line)


def get_easyconfig_file_name_by_convention(app):
    eb_app_string = app['app_name'] + '-' + app['app_vers']
    if (app['tc_name'] != 'dummy'):
        eb_app_string += '-' + app['tc_name'] + '-' + app['tc_vers']
    if (app['app_vers_suffix'] != ''):
        eb_app_string += app['app_vers_suffix']
    return(eb_app_string)


def get_needy_dependants(dep_level, catalog, q_app, q_app_is_toolchain):
    dep_level += 1
    #
    # Find dependant apps where "dep" is listed as a dependency.
    #
    for app in catalog:
        logging.debug('Processing app ' + app['app_name'] +
                      ' (dep level = ' + str(dep_level) + ')...')
        logging.debug(json.dumps(app, indent=4, sort_keys=True))
        app_is_dependant = False
        if q_app_is_toolchain is True:
            if (app['tc_name'] == q_app['app_name']
                    and app['tc_vers'] == q_app['app_vers']):
                #
                # We found a correctly specified dependency.
                #
                app_is_dependant = True
        for dep in app['run_deps']:
            if q_app_is_toolchain is True:
                if (dep['tc_name'] == q_app['app_name']
                        and dep['tc_vers'] == q_app['app_vers']):
                    #
                    # We found a correctly specified dependency.
                    #
                    app_is_dependant = True
                elif (q_app['app_name'] + '-' + q_app['app_vers'] in dep['app_vers']
                        or q_app['app_name'] + '-' + q_app['app_vers'] in dep['app_vers_suffix']):
                    #
                    # We found a malformed dependency.
                    #
                    logging.error('Malformed dependency: tool chain in either '
                                  'the version number or version suffix!')
                    logging.error('\towner: ' + app['owner'] +
                                  ' | deployed easyconfig: ' + app['easyconfig'])
                    app_is_dependant = True
            elif (dep['app_name'] == q_app['app_name']):
                if (dep['app_vers'] == q_app['app_vers']
                        and dep['app_vers_suffix'] == q_app['app_vers_suffix']
                        and dep['tc_name'] == q_app['tc_name']
                        and (dep['tc_vers'] == q_app['tc_vers']
                             or dep['tc_name'] == 'dummy')):
                    #
                    # We found a correctly specified dependency.
                    #
                    app_is_dependant = True
                elif(dep['app_vers'] == q_app['app_vers']
                        and dep['app_vers_suffix'] ==
                        '-' + q_app['tc_name'] + '-'
                        + q_app['tc_vers']
                        + q_app['app_vers_suffix']):
                    #
                    # We found a malformed dependency.
                    #
                    logging.error('Malformed dependency: tool chain in either '
                                  'the version number or version suffix!')
                    logging.error('\towner: ' + app['owner'] +
                                  ' | deployed easyconfig: ' + app['easyconfig'])
                    app_is_dependant = True
                elif(dep['app_vers'] ==
                     q_app['app_vers'] + '-'
                     + q_app['tc_name'] + '-'
                     + q_app['tc_vers']
                     + q_app['app_vers_suffix']):
                    #
                    # We found a malformed dependency.
                    #
                    logging.error('Malformed dependency: tool chain in either '
                                  'the version number or version suffix!')
                    logging.error('\towner: ' + app['owner'] +
                                  ' | deployed easyconfig: ' + app['easyconfig'])
                    app_is_dependant = True
        if app_is_dependant is True:
            format_and_print(dep_level, app)
            get_needy_dependants(dep_level, catalog, app, False)


def get_requirements(dep_level, catalog, q_app, include_toolchain_as_req):
    dep_level += 1
    #
    # Find both "run_dep" as well as "build_deps".
    #
    logging.debug('Processing app ' + q_app['app_name'] +
                  ' (dep level = ' + str(dep_level) + ')...')
    logging.debug(json.dumps(q_app, indent=4, sort_keys=True))
    req_types = ('build_deps', 'run_deps')
    for req_type in req_types:
        logging.debug('Processing "' + req_type + '" requirements...')
        for req in q_app[req_type]:
            logging.debug('Processing requirement '
                          + get_easyconfig_file_name_by_convention(req)
                          + '...')
            req_found_in_catalog = False
            for app in catalog:
                if (app['app_name'] == req['app_name']
                        and app['app_vers'] == req['app_vers']
                        and app['app_vers_suffix'] == req['app_vers_suffix']
                        and app['tc_name'] == req['tc_name']
                        and (app['tc_vers'] == req['tc_vers']
                             or req['tc_name'] == 'dummy')):
                    #
                    # We found the correctly specified dependency.
                    #
                    format_and_print(dep_level, app)
                    logging.debug('Found requirement '
                                  + get_easyconfig_file_name_by_convention(req)
                                  + '.')
                    req_found_in_catalog = True
                    get_requirements(dep_level, catalog, app, False)
                    break
            if req_found_in_catalog is False:
                logging.error('Required "' + req_type + '" requirement '
                              + get_easyconfig_file_name_by_convention(req)
                              + ' for app '
                              + get_easyconfig_file_name_by_convention(q_app)
                              + ' is missing from the catalog.')
                logging.error('If the requirement does appear to be installed, '
                              'then check for naming convention violations like '
                              'toolchain name and version erroneously listed '
                              'in application version (suffix).')
    if include_toolchain_as_req is True and q_app['tc_name'] != 'dummy':
        logging.debug('Processing "toolchain" requirement '
                      + q_app['tc_name'] + '-' + q_app['tc_vers'] + '...')
        req_found_in_catalog = False
        for app in catalog:
            if (app['app_name'] == q_app['tc_name']
                    and (app['app_vers'] == q_app['tc_vers']
                         or app['app_vers'] + app['app_vers_suffix'] == q_app['tc_vers'])
                    and app['tc_name'] == 'dummy'):
                #
                # We found the correctly specified toolchain.
                #
                logging.debug('Found requirement.')
                req_found_in_catalog = True
                format_and_print(dep_level, app)
                get_requirements(dep_level, catalog, app, True)
                break
        if req_found_in_catalog is True:
            logging.debug('Found "toolchain" requirement '
                          + get_easyconfig_file_name_by_convention(app) + '.')
        else:
            logging.error('Required "toolchain" '
                          + q_app['tc_name'] + '-' + q_app['tc_vers']
                          + ' for app '
                          + get_easyconfig_file_name_by_convention(q_app)
                          + ' is missing from the catalog.')


if __name__ == "__main__":
    main()
