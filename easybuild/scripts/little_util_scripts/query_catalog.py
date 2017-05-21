#!/usr/bin/env python
from __future__ import print_function
import argparse
import json
import logging
import os
import subprocess
import sys


#
# This program queries a catalog in JSON format of all software installed by EasyBuild.
# The catalog must be created with create_catalog.py before you can use this script.
#


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
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-c', '--catalog',
                        help='Catalog flatfile '
                             'where list of installed software modules will be saved.',
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
    parser.add_argument('-d', '--deps',
                        help='List dependent software. '
                             'Hence modules depending on the one specified.',
                        action='store_true',
                        default=False)
    parser.add_argument('-r', '--reqs',
                        help='List required software. '
                             'Hence modules required for the one specified.',
                        action='store_true',
                        default=False)
    parser.add_argument('-m', '--messages',
                        help='Create (Lmod admin) Messages file. '
                             'Will print extra messages when a module is loaded with Lmod.'
                             'Can be used to warn users that a module is deprecated '
                             'and scheduled for removal',
                        action='store_true',
                        default=False)
    parser.add_argument('-l', '--loglevel',
                        help='Log level. One of DEBUG, INFO, WARNING, ERROR or CRITICAL.',
                        default='INFO')
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
    if isinstance(catalog_file, basestring) and os.path.isfile(catalog_file):
        logging.info('Querying EasyBuild installed software catalog ' + catalog_file + '...')
    else:
        logging.critical('Please provide the path to the catalog file using either '
                         'the EASYBUILD_CATALOG environment variable or'
                         'the -c/--catalog command line argument.')
        sys.exit(2)
    #
    # Get query app and optional version + toolchain + toolchain version.
    #
    if isinstance(args.app, basestring):
        q_app_string = args.app
        q_app = q_app_string.split('/', 1)
        q_app_name = q_app[0]
        logging.debug('Will query catalog for application named: ' + q_app_name)
        if len(q_app) == 2:
            q_app_vers = q_app[1]
            logging.debug('Will query catalog for application version: ' + q_app_vers)
        else:
            q_app_vers = None
            logging.debug('No application version specified.')
    else:
        logging.critical('Must provide an application to query the catalog for with -a/--app')
        sys.exit(2)
    if isinstance(args.tc, basestring):
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
    #
    # Get requested action.
    #
    if isinstance(args.deps, bool):
        list_deps = args.deps
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
        if (app['app_name'] == q_app_name
                and (app['app_vers'] == q_app_vers or q_app_vers is None)
                and (app['tc_name'] == q_tc_name or q_tc_name is None)
                and (app['tc_vers'] == q_tc_vers or q_tc_vers is None)):
            #
            # Application matches query terms.
            #
            logging.debug('App ' + app['app_name'] + ' matches query terms.')
            print("{0}".format(separator))
            format_and_print(dep_level, app)
            if list_deps:
                get_needy_dependants(dep_level, catalog, app)


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
    formatted_line = "{0}: {1}{2}".format(
        dep_level, indent, ml_app_string)
    #
    # Print.
    #
    print(formatted_line)


def get_needy_dependants(dep_level, catalog, dep_app):
    dep_level += 1
    #
    # Find dependant apps where "dep" is listed as a dependency.
    #
    for app in catalog:
        logging.debug('Processing app ' + app['app_name'] +
                      ' (dep level = ' + str(dep_level) + ')...')
        logging.debug(json.dumps(app, indent=4, sort_keys=True))
        for dep in app['run_deps']:
            if (dep['app_name'] == dep_app['app_name']):
                if (dep['app_vers'] == dep_app['app_vers']
                        and dep['app_vers_suffix'] == dep_app['app_vers_suffix']
                        and dep['tc_name'] == dep_app['tc_name']
                        and (dep['tc_vers'] == dep_app['tc_vers']
                             or dep['tc_name'] == 'dummy')):
                    #
                    # We found a correctly specified dependency.
                    #
                    format_and_print(dep_level, app)
                    get_needy_dependants(dep_level, catalog, app)
                elif(dep['app_vers'] == dep_app['app_vers']
                        and dep['app_vers_suffix'] ==
                        '-' + dep_app['tc_name'] + '-'
                        + dep_app['tc_vers']
                        + dep_app['app_vers_suffix']):
                    #
                    # We found a malformed dependency.
                    #
                    logging.error('Malformed dependency: tool chain in either '
                                  'the version number or version suffix!')
                    logging.error('\towner: ' + app['owner'] +
                                  ' | deployed easyconfig: ' + app['easyconfig'])
                    format_and_print(dep_level, app)
                    get_needy_dependants(dep_level, catalog, app)
                elif(dep['app_vers'] ==
                     dep_app['app_vers'] + '-'
                     + dep_app['tc_name'] + '-'
                     + dep_app['tc_vers']
                     + dep_app['app_vers_suffix']):
                    #
                    # We found a malformed dependency.
                    #
                    logging.error('Malformed dependency: tool chain in either '
                                  'the version number or version suffix!')
                    logging.error('\towner: ' + app['owner'] +
                                  ' | deployed easyconfig: ' + app['easyconfig'])
                    format_and_print(dep_level, app)
                    get_needy_dependants(dep_level, catalog, app)


if __name__ == "__main__":
    main()
