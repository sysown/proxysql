# Packaging

### How do I package ProxySQL for all the platforms it supports?

The simplest way is to go to the root folder of the repo and run "make packages". This command assumes that you have Docker installed. This will create 2 new packages in the "binaries" folder, one for Ubuntu 14.04 and one for CentOS. Other operating systems are coming soon!

#### Frequent errors

If you're getting an error like this from the packaging script:
"FATA[0000] Error response from daemon: Conflict. The name "ubuntu14_build" is already in use by container d4c8dface7bc. You have to delete (or rename) that container to be able to reuse that name."

.. then all you have to do is run docker rm ubuntu14_build (or the equivalent container name it complains about) and re-run the packaging script.

#### How long does the packaging take?

Each run will take up to 20 minutes. The reason is that it's pulling the fresh package from the source and recompiling ProxySQL against those versions of packages. This can be optimized by reducing to about half of the time if needed, by making use of the Docker layer caching mechanism. Right now we're bypassing it completely in order to be sure that we're always building the latest source tree for ProxySQL into a package.

#### Which operating system can I run the packaging on?

In theory, it should work on any debian-based operating system. We only tested it on Ubuntu 14.04 so far. However, it should work at least on othe flavours of Linux as well. The most important thing it depends on is Docker's ability to run containers for the supported operating systems on top of another operating system. If this proves to be unfeasible, we'll move away from Docker containers to real VMs on the long run.

