#!/usr/bin/env python
from __future__ import print_function

import argparse
import json
import logging
import os
import pwd
import sys


try:
    # from easybuild.framework.easyconfig.format.format import Dependency
    # from easybuild.framework.easyconfig.format.version import EasyVersion
    from easybuild.framework.easyconfig.parser import EasyConfigParser
except ImportError:
    if 'EBROOTEASYBUILD' in os.environ:
        print('CRITICAL: EasyBuild was loaded as module, but ' + sys.argv[0]
              + ' failed to import Python API modules:',
              file=sys.stderr
              )
        raise
    else:
        print('CRITICAL: EasyBuild was not loaded as module.', file=sys.stderr)
        print('CRITICAL: Try', file=sys.stderr)
        print('              module load EasyBuild', file=sys.stderr)
        print('          before running ' + sys.argv[0] + '.', file=sys.stderr)
        sys.exit(1)

#
# This program creates a catalog in JSON format of all software installed by EasyBuild.
# It walks the directory tree recursively starting by default at EASYBUILD_INSTALLPATH
# and parses any *.eb files found.
# The EasyBuild module should be loaded before executing this script.
#
# It is useful to store the catalog in a location accessible for all users.
# The flatfile catalog can be used by other scripts such as:
#                query_toolchain.py       --- lists toolchain for some
#                                               software/version
#                query_dependency.py      --- reverse dependency lookup
#                ec_manager.py            --- manages easyconfig collections
#                find_not_dependency.py   --- lists programs that are not
#                                                dependencies of any others
# Based on original script from EB Gregory 25 Feb 2015
#


def main():
    #
    # Get commandline options.
    #
    if 'EASYBUILD_SUBDIR_SOFTWARE' in os.environ:
        easybuild_subdir_software = os.environ['EASYBUILD_SUBDIR_SOFTWARE']
    else:
        easybuild_subdir_software = 'software'  # default
    if 'EASYBUILD_INSTALLPATH' in os.environ:
        default_top_dir = os.environ['EASYBUILD_INSTALLPATH'] + '/' \
                          + easybuild_subdir_software + '/'
    else:
        default_top_dir = None
    parser = argparse.ArgumentParser(
        description='Builds a catalog of software installed by EasyBuild.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('-t', '--topdir',
                        help='Top directory to search recursively for installed software.',
                        default=default_top_dir)
    parser.add_argument('-c', '--catalog',
                        help='Catalog file where list of installed software will be saved.',
                        default='installed_with_easybuild.json')
    parser.add_argument('-f', '--force',
                        help='Force overwrite catalog file if it already exists.',
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
    # Get topdir.
    #
    top = args.topdir
    if isinstance(top, basestring) and os.path.isdir(top):
        logging.info('Searching for installed easyconfigs in ' + top + '...')
    else:
        logging.critical('Please provide a search path using either '
                         'the EASYBUILD_INSTALLPATH environment variable or'
                         'the -t/--topdir command line argument.')
        sys.exit(2)
    #
    # Get catalog file path.
    #
    catalog = args.catalog
    if isinstance(catalog, basestring) and os.path.isfile(catalog):
        if args.force is False:
            logging.critical('Catalog file ' + catalog + ' already exists.')
            logging.critical('Specify another file name or '
                             'use "--force" to overwrite the existing catalog.')
            sys.exit(1)
    else:
        logging.info('Will save the catalog to ' + catalog)
    #
    # Find and parse easyconfigs.
    #
    exten = '.eb'
    applications = []
    easyconfigs_found = 0
    easyconfigs_parsed = 0
    exclude = set(['EasyBuild'])
    exclude_sstr = ".sys."
    for root, dirs, files in os.walk(top, topdown=True):
        dirs[:] = [d for d in dirs if d not in exclude]
        for name in files:
            # the exclude_sstr part should be improved
            if (name.lower().endswith(exten) and (exclude_sstr not in name)):
                eb_file = os.path.join(root, name)
                easyconfigs_found += 1
                app_dict = parse_eb_file(eb_file)
                if app_dict is None:
                    logging.warning("Failed to parse: {0}".format(eb_file))
                else:
                    applications.append(app_dict)
                    easyconfigs_parsed += 1
    logging.info('Parsed ' + str(easyconfigs_parsed) + '/'
                 + str(easyconfigs_found) + ' easyconfigs.')
    applications.sort(key=by_name_vers)
    #
    # Save catalog to file.
    #
    catalog_fh = open(catalog, 'w')
    catalog_fh.write(json.dumps(applications, indent=4, sort_keys=True))
    catalog_fh.close()
    logging.info('Saved apps to catalog ' + catalog)
    logging.info('Finished!')


def by_name_vers(app_dict):
    app_name = app_dict.get("app_name")
    app_vers = app_dict.get("app_vers")
    nv = app_name+"-"+app_vers
    return nv


def parse_eb_file(easyconfig):
    logging.debug("Parsing: {0}...".format(easyconfig))
    ecp = EasyConfigParser(easyconfig)
    ec = ecp.get_config_dict()
    owner = pwd.getpwuid(os.stat(easyconfig).st_uid).pw_name
    app_name = ec.get('name')
    app_vers = ec.get('version')
    logging.debug("Parsing EasyConfig {0}\t{1}".format(app_name, app_vers))
    tc_name = ec.get('toolchain', dict()).get('name')
    tc_vers = ec.get('toolchain', dict()).get('version')
    #
    # Verify that this easyconfig file meets the minimal requirements.
    #
    if (not app_name):
        logging.error('Failed to parse EasyConfig: name is mandatory.')
        return
    if (not app_vers):
        logging.error('Failed to parse EasyConfig: version is mandatory.')
        return
    if (not tc_name):
        logging.error('Failed to parse EasyConfig: toolchain name is mandatory.')
        return
    if ((not tc_vers) and (tc_name != 'dummy')):
        logging.error('Failed to parse EasyConfig: toolchain version is mandatory.')
        return
    #
    # Get optional easyconfig specs.
    #
    app_vers_suffix = ec.get('versionsuffix', '')
    # vpref = ec.get('versionprefix', '')
    deps = ec.get("dependencies")
    build_deps = ec.get("builddependencies")
    if deps:
        formatted_deps = format_deps(easyconfig, deps, tc_name, tc_vers)
    else:
        formatted_deps = []
    if build_deps:
        formatted_build_deps = format_deps(easyconfig, build_deps, tc_name, tc_vers)
    else:
        formatted_build_deps = []
    #
    # Sanity check for common mistakes.
    #
    sanity_check(easyconfig, app_vers, app_vers_suffix)
    #
    # Return app dict
    #
    return {'app_name': app_name, 'app_vers': app_vers, 'app_vers_suffix': app_vers_suffix,
            'tc_name': tc_name, 'tc_vers': tc_vers,
            'run_deps': formatted_deps, 'build_deps': formatted_build_deps,
            'owner': owner, 'easyconfig': easyconfig}


def format_deps(easyconfig, deps, app_tc_name, app_tc_vers):
    dependencies = []
    numdeps = len(deps)
    for i in range(0, numdeps):
        dep_name = deps[i][0]
        dep_vers = deps[i][1]
        #
        # When no explicit toolchain is specified for the dependency,
        # it will inherit the toolchain from the app.
        #
        dep_vers_suffix = ''
        dep_tc_name = app_tc_name
        dep_tc_vers = app_tc_vers
        if len(deps[i]) > 2:
            dep_vers_suffix = deps[i][2]
            if len(deps[i]) > 3:
                if deps[i][3] is True:
                    dep_tc_name = 'dummy'
                    dep_tc_vers = ''
                else:
                    dep_tc_name = deps[i][3][0]
                    dep_tc_vers = deps[i][3][1]
        sanity_check(easyconfig, dep_vers, dep_vers_suffix)
        app_dict = {'app_name': dep_name, 'app_vers': dep_vers, 'app_vers_suffix': dep_vers_suffix,
                    'tc_name': dep_tc_name, 'tc_vers': dep_tc_vers}
        dependencies.append(app_dict)
    dependencies.sort(key=by_name_vers)
    return dependencies


def sanity_check(easyconfig, vers, vers_suffix):
    #
    # Sanity check for common mistakes:
    #  * tool chain must be listed as tool chain
    #    and not as part of the version number nor as version suffix.
    if ('foss' in vers) or ('goolf' in vers):
        logging.error('Toolchain erroneously listed '
                      'in the version ' + vers +
                      ' of easyconfig ' + easyconfig + '.')
    if ('foss' in vers_suffix) or ('goolf' in vers_suffix):
        logging.error('Toolchain erroneously listed '
                      'in the version suffix ' + vers_suffix +
                      ' of easyconfig ' + easyconfig + '.')


if __name__ == "__main__":
    main()
