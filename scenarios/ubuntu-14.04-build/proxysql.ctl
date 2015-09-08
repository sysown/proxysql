### Commented entries have reasonable defaults.
### Uncomment to edit them.
# Source: <source package name; defaults to package name>
Section: misc
Priority: optional
# Homepage: <enter URL here; no default>
Standards-Version: 3.9.2

Package: proxysql
Version: 0.3
Maintainer: Rene Cannao <rene.cannao@gmail.com>
# Pre-Depends: <comma-separated list of packages>
# Depends: <comma-separated list of packages>
# Recommends: <comma-separated list of packages>
# Suggests: <comma-separated list of packages>
# Provides: <comma-separated list of packages>
# Replaces: <comma-separated list of packages>
# Architecture: all
# Copyright: <copyright file; defaults to GPL2>
# Changelog: <changelog file; defaults to a generic changelog>
# Readme: <README.Debian file; defaults to a generic one>
# Extra-Files: <comma-separated list of additional files for the doc directory>
Files: proxysql /opt/proxysql
 proxysql.cfg /etc 
#  <more pairs, if there's more than one file to include. Notice the starting space>
Description: High performance MySQL proxy
 long description and info
 .
 second paragraph
File: postinst
 #!/bin/sh -e
 mkdir -p /var/run/proxysql