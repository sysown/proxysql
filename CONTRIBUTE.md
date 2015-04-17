# How to setup a development environment for yourself

1. Install VirtualBox + Ubuntu 14.04 (needs recent gcc/g++ compiler versions)
2. Install the following packages via apt:
  2.1 make
  2.2 cmake
  2.3 gcc
  2.4 g++
  2.5 libssl-dev
  2.6 mysql-server
  2.7 libmysqlclient-dev (for compiling perf test)
3. Create a fork of proxysql in your GitHub account. Example: https://github.com/aismail/proxysql-0.2
4. Add a new git remote so that you will be able to pull code from upstream:
  git remote add sysown git@github.com:sysown/proxysql-0.2.git

  From now on, when you are working on a feature branch, make sure to update
  the changes with those from upstream by doing:
    git pull --rebase sysown master (rebase is important because it will keep yoru commits grouped together)
    git push origin yourbranch

  When you are finished working on the feature branch, create a pull request
  to sysown/master and take it from there
5. Install VirtualBox guest additions in the Ubuntu VM.
6. Add the proxysql-0.2 folder to Shared folders in VirtualBox (but make sure that auto-mount and read-only are not checked)
7. Edit /etc/rc.local in the virtual machine to include this line before exit 0:
mount -t vboxsf -o rw,uid=1000,gid=1000 proxysql-0.2 /home/aismail/proxysql-0.2/
  This will mount the shared code from your computer to the virtual machine with
  the correct permissions.
8. You need to go to your host OS and make sure you enable symlinks inside the shared folder (they are currently disabled for security reasons). This is required for the Makefile to work correctly:
  VBoxManage setextradata ProxySQL VBoxInternal2/SharedFoldersEnableSymlinksCreate/proxysql-0.2 1

  In my case, ProxySQL is the name of the VM as defined in VirtualBox, and proxysql-0.2 is the name of the mountpoint as defined in shared folders.
9. Shut down virtual machine and start it again.
10. Go to the proxysql-0.2 folder in the virtual machine, and do "make". This will compile the code and it should work without any problems at this point
11. To run the server, you need a config file (see provided example), and the main binary is currently located in src/proxysql
12. Run netstat -tlnp to see the port it opens. By default, you'll want to connect to 6033
