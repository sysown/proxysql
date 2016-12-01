#!/usr/bin/python

"""scenarios management tool

Usage:
    scenarios.py <command> [<args>...]
    scenarios.py start [<scenario>]
    scenarios.py build_image [<image>]

The most commonly used scenarios.py commands are:
   list                 List the available test scenarios
   proxysql_versions    List the available ProxySQL versions to be tested
   mysql_versions       List the available MySQL versions to be paired with ProxySQL for testing
   start                Start a ProxySQL testing scenario
   ps                   List the running ProxySQL scenarios
"""
import os
import subprocess
import sys

from docopt import docopt
import nose

from docker_fleet import DockerFleet

PROXYSQL_SCENARIO_FILE = '/tmp/proxysql-scenario.txt'

def scenarios_list():
    templates = DockerFleet().get_docker_scenario_templates()
    scenario_names = sorted(templates.keys())
    for scenario in scenario_names:
        print('%s @ %s' % (scenario, os.path.abspath(templates[scenario]['dir'])))

def proxysql_images():
    dockerfiles = DockerFleet().get_dockerfiles_for_proxysql()
    images = sorted(dockerfiles.keys())
    for image in images:
        print('%s @ %s' % (image, os.path.abspath(dockerfiles[image]['dir'])))

def mysql_images():
    dockerfiles = DockerFleet().get_dockerfiles_for_mysql()
    images = sorted(dockerfiles.keys())
    for image in images:
        print('%s @ %s' % (image, os.path.abspath(dockerfiles[image]['dir'])))

def start(scenario, proxysql_image, mysql_image):
    docker_fleet = DockerFleet()
    scenario_info = docker_fleet.generate_scenarios(
        scenarios=[scenario],
        proxysql_filters={'names': [proxysql_image]},
        mysql_filters={'names': [mysql_image]}
    )[0]
    dirname = docker_fleet.start_temp_scenario(scenario_info, copy_folder=True)
    with open(PROXYSQL_SCENARIO_FILE, 'wt') as f:
        f.write(dirname)
    return dirname

def stop():
    with open(PROXYSQL_SCENARIO_FILE, 'rt') as f:
        dirname = ''.join(f.readlines()).strip()
        DockerFleet().stop_temp_scenario(dirname, delete_folder=True)
    try:
        os.remove(PROXYSQL_SCENARIO_FILE)
    except:
        pass

def _build_image(image, dir):
    subprocess.call(["docker", "rmi", "-f", "proxysql:%s" % image])
    subprocess.call(["docker", "build", "-t", "proxysql:%s" % image, "."],
                    cwd=dir)

def build_image(image):
    if image != 'all':
        # Builds a docker image (either for ProxySQL or for MySQL) and commits it
        # to the renecannao dockerhub repository.
        dockerfiles = DockerFleet().get_dockerfiles_for_proxysql()
        if image in dockerfiles:
            _build_image(image, dockerfiles[image]['dir'])
            return
        
        dockerfiles = DockerFleet().get_dockerfiles_for_mysql()
        if image in dockerfiles:
            _build_image(image, dockerfiles[image]['dir'])
            return

        print("Image %s wasn't found in either ProxySQL or MySQL image list.\n"
              "Please double-check the name!" % image)
    else:
        dockerfiles = DockerFleet().get_dockerfiles_for_proxysql()
        for image in dockerfiles.iterkeys():
            _build_image(image, dockerfiles[image]['dir'])

        dockerfiles = DockerFleet().get_dockerfiles_for_mysql()
        for image in dockerfiles.iterkeys():
            _build_image(image, dockerfiles[image]['dir'])

def test(argv):
    nose.run(argv=argv)

if __name__ == '__main__':

    args = docopt(__doc__,
                  version='scenarios.py version 0.0.1',
                  options_first=True)

    argv = [args['<command>']] + args['<args>']
    if args['<command>'] == 'list':
        scenarios_list()
    elif args['<command>'] == 'proxysql_images':
        proxysql_images()
    elif args['<command>'] == 'mysql_images':
        mysql_images()
    elif args['<command>'] == 'start':
        if len(args['<args>']) >= 1:
            scenario = args['<args>'][0]
        else:
            # Default value for the scenario parameter: '1backend'
            scenario = '1backend'

        if len(args['<args>']) >= 2:
            proxysql_image = args['<args>'][1].split('=')[1]
        else:
            # Default value for the proxysql_image parameter: 'proxysql'
            proxysql_image = 'proxysql'

        if len(args['<args>']) >= 3:
            mysql_image = args['<args>'][2].split('=')[1]
        else:
            # Default value for the mysql_image parameter: 'mysql-simple-dump'
            mysql_image = 'mysql-simple-dump'

        if (os.path.exists(PROXYSQL_SCENARIO_FILE)):
            print("Is there another scenario running? If not, delete %s" %
                  PROXYSQL_SCENARIO_FILE)
        else:
            dirname = start(scenario, proxysql_image, mysql_image)
            print("Scenario started successfully at path %s" % dirname)

    elif args['<command>'] == 'stop':
        if (not os.path.exists(PROXYSQL_SCENARIO_FILE)):
            print("There is no scenario running or file %s has been removed" %
                  PROXYSQL_SCENARIO_FILE)
        else:
            stop()
            print("Scenario stopped successfully")

    elif args['<command>'] == 'build_image':
        if len(args['<args>']) > 0:
            build_image(args['<args>'][0])
        else:
            build_image('all')

    elif args['<command>'] == 'test':
        if (not os.path.exists(PROXYSQL_SCENARIO_FILE)):
            print("There doesn't seem to be a running scenario. Aborting.")
        else:
            if len(args['<args>']) > 0:
                test(args['<args>'])
            else:
                test(['.'])