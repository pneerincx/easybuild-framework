#!/usr/bin/env python
from __future__ import print_function
import sys
import os
# import time
import pwd
import logging
import argparse

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
# This program creates a (flatfile) "catalog" of all software installed by EasyBuild.
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
                        help='Catalog flatfile where list of installed software will be saved.',
                        default='installed_with_easybuild.catalog')
    parser.add_argument('-l', '--loglevel',
                        help='Log level. One of DEBUG, INFO, WARNING, ERROR or CRITICAL',
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
                        level=numeric_level,
                        format='%(filename)s:%(lineno)s %(levelname)s:%(message)s')
    logging.info('Started...')
    #
    # Get topdir.
    #
    top = args.topdir
    if os.path.isdir(top):
        logging.info('Searching for installed easyconfigs in ' + top + '...')
    else:
        logging.critical('Please define the environment variable EASYBUILD_INSTALLPATH '
                         'or provide a search path with the -t TOPDIR command line argument.')
        sys.exit(2)
    
    exten = '.eb'
    applications = []

    num_apps = 0

    exclude = set(['EasyBuild'])
    exclude_sstr = ".sys."

    for root, dirs, files in os.walk(top, topdown=True):
        dirs[:] = [d for d in dirs if d not in exclude]

        for name in files:
            # the exclude_sstr part should be improved
            if (name.lower().endswith(exten) and (exclude_sstr not in name)):
                eb_file = os.path.join(root, name)

                app_dict = parse_eb_file(eb_file)

                if app_dict is None:
                    logging.warning("Failed to parse: {0}".format(eb_file))
                else:
                    applications.append(app_dict)
                    num_apps += 1

    applications.sort(key=by_name_vers)

    for app in applications:
        app_name = app.get('name')
        app_vers = app.get('vers')
        app_tc = app.get('tc_name')
        app_tcvers = app.get('tc_vers')
        app_owner = app.get('owner')
        app_ebfile = app.get('ebfile')

        print("APP {0}\t{1}\t{2}\t{3}\t{4}".format(app_name, app_vers,
                                                   app_tc, app_tcvers,
                                                   app_owner))
        print("FILE {0}".format(app_ebfile))
        if app.get('deps'):
            app_deps = app.get('deps')
            numdeps = len(app_deps)
            for i in range(numdeps):
                dep_name = app_deps[i][0]
                dep_vers = app_deps[i][1]
                dep_vers_suffix = ''
                dep_tc = app_tc
                dep_tc_vers = app_tcvers
                if len(app_deps[i]) > 2:
                    dep_vers_suffix = app_deps[i][2]

                if len(app_deps[i]) > 3:
                    if app_deps[i][3] is True:
                        dep_tc = 'dummy'
                        dep_tc_vers = '-'
                    else:
                        dep_tc = app_deps[i][3][0]
                        dep_tc_vers = app_deps[i][3][1]

                dep_vers = dep_vers+dep_vers_suffix
                print("\tDEP {0}\t{1}\t{2}\t{3}".format(
                      dep_name, dep_vers, dep_tc, dep_tc_vers))


def by_name_vers(app_dict):
    app_name = app_dict.get("name")
    app_vers = app_dict.get("vers")
    nv = app_name+"-"+app_vers
    return nv


def parse_eb_file(eb_file):

    ecp = EasyConfigParser(eb_file)

    ec = ecp.get_config_dict()
    owner = pwd.getpwuid(os.stat(eb_file).st_uid).pw_name

    name = ec.get('name')
    vers = ec.get('version')

    logging.debug("Parsing EasyConfig {0}\t{1}".format(name, vers))

    tc_name = ec.get('toolchain', dict()).get('name')
    tc_vers = ec.get('toolchain', dict()).get('version')

    # check that this file has the basics of an easyconfig
    if (not name):
        logging.error('Failed to parse EasyConfig: name is mandatory.')
        return
    if (not vers):
        logging.error('Failed to parse EasyConfig: version is mandatory.')
        return
    if (not tc_name):
        logging.error('Failed to parse EasyConfig: toolchain name is mandatory.')
        return
    if ((not tc_vers) and (tc_name != 'dummy')):
        logging.error('Failed to parse EasyConfig: toolchain version is mandatory.')
        return

    vsuff = ec.get('versionsuffix', '')
    vpref = ec.get('versionprefix', '')
    vers = vpref+vers+vsuff

    deps = ec.get("dependencies")
    # also check for build dependencies, which are listed
    # separately in the eb file

    builddeps = ec.get("builddependencies")

    if builddeps:
        if deps:
            deps.extend(builddeps)
        else:
            deps = builddeps

    if deps:
        numdeps = len(deps)

        for i in range(0, numdeps):

            dep_name = deps[i][0]
            dep_vers = deps[i][1]

            # default is dependency toolchain is the same
            # and no dependency version suffix
            # unless we hear otherwise
            dep_vers_suffix = ""
            dep_tc = tc_name
            dep_tc_vers = tc_vers

            if len(deps[i]) > 2:
                dep_vers_suffix = deps[i][2]

                if len(deps[i]) > 3:

                    if deps[i][3] is True:
                        dep_tc = 'dummy'
                        dep_tc_vers = '-'
                    else:
                        dep_tc = deps[i][3][0]
                        dep_tc_vers = deps[i][3][1]

            dep_vers += dep_vers_suffix

    return {'name': name, 'vers': vers, 'tc_name': tc_name, 'tc_vers': tc_vers,
            'owner': owner, 'deps': deps, 'ebfile': eb_file}


if __name__ == "__main__":
    main()
