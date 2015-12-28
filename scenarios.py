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

from docopt import docopt

from test.docker_fleet import DockerFleet

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

def start(scenario, proxysql_version, mysql_version):
    # TODO(andrei): store somewhere details so that we don't need to pass
    # any args to stop(), making it easier
    pass

def stop():
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
        start()
    elif args['<command>'] == 'stop':
        stop()
    elif args['<command>'] == 'build_image':
        if len(args['<args>']) > 0:
            build_image(args['<args>'][0])
        else:
            build_image('all')