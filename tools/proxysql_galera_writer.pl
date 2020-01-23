#!/usr/bin/perl
use strict;
use warnings;
use vars;
use DBI;
use DBD::mysql;


## CUSTOMIZE THESE CONSTANTS
use constant {
	HOST => "127.0.0.1",
	PORT => "6032",
	USER => "admin",
	PASS => "admin",
	VERB => 1
};

our $dbn;
our $dbh;

sub main {
	@ARGV = @_;
	my $nargs=$#ARGV + 1;
	if ($nargs != 3) {
		print STDERR "Incorrect number of arguments\n";
		return 1;
	}
	my $writerHG=$ARGV[0];
	my $readerHG=$ARGV[1];
	my $maxwriters=$ARGV[2];
	if (VERB) {
		print STDERR "Writer hostgroup: $writerHG\n";
		print STDERR "Reader hostgroup: $readerHG\n";
		print STDERR "Max num writers:  $maxwriters\n";
	}
	# connect to Admin interface and retrieve the current ative masters
	$dbn="dbi:mysql:main:".HOST.":".PORT;
	$dbh=DBI->connect($dbn, USER, PASS) or die "Unable to connect: $DBI::errstr\n";
	my $selh=$dbh->prepare("SELECT hostname,port FROM runtime_mysql_servers WHERE status='ONLINE' AND hostgroup_id=$writerHG") or die "Unable to prepare: $DBI::errstr\n";
	$selh->execute() or die "Unable to execute: $DBI::errstr\n";
	my @data;
	while (my $res=$selh->fetchrow_hashref) {
		push (@data, $res);
	}
	my $active_writers= scalar @data;
	if (VERB) {
		print STDERR "Active writers found: $active_writers\n";
		foreach (@data) {
			my $s=$_;
			print "	$s->{'hostname'} $s->{'port'}\n";
		}
	}
	if ($active_writers==$maxwriters) {
		if (VERB) {
			print STDERR "Active writers match max number of writers: exit with no action\n";
		}
		return 0;
	}
	# if the execution of the script reaches here, some action is required
	if (VERB) {
		print STDERR "$active_writers active writers found do not match $maxwriters writers expected\n";
	}
	# although we run the check on runtime_mysql_servers , we will perform all the operations on mysql_servers
	# be aware that in ProxySQL Admin doesn't support locking or transactions, so, even if unlikely,
	# it is possible that race conditions can happen if two scripts update mysql_servers at the same

	# first, set to OFFLINE_SOFT all nodes in the writer hostgroup
	# OFFLINE_SOFT doesn't terminate current transactions, therefore it is a graceful "shutdown"
	print STDERR "Disabling old $active_writers write(s)\n";	
	$dbh->do("UPDATE mysql_servers SET status='OFFLINE_SOFT' WHERE hostgroup_id=$writerHG") or die "Unable to set writes offline: $DBI::errstr\n";

	# here we define the new masters
	# the algorithm used to determine the new masters is customizable: define the algorithm you prefer
	# CUSTOMIZE IT!
	print STDERR "Adding new $maxwriters write(s)\n";	

	# in this example, the algorithm is that are promoted as master(s) the first N hosts order by ORDER BY weight DESC, hostname, port
	$dbh->do("REPLACE INTO mysql_servers (hostgroup_id, hostname, port, status, weight, max_connections, connection_warming, use_ssl) SELECT $writerHG , hostname, port, status, weight, max_connections, connection_warming, use_ssl FROM mysql_servers WHERE hostgroup_id=$readerHG AND status='ONLINE' ORDER BY weight DESC, hostname, port LIMIT $maxwriters") or die "Unable to set new writer: $DBI::errstr\n";

	# now we load at RUNTIME
	print STDERR "Loading to runtime...";
	$dbh->do("LOAD MYSQL SERVERS TO RUNTIME") or die "Unable to LOAD MYSQL SERVERS TO RUNTIME: $DBI::errstr\n";
	print STDERR " Done!\n";
	# as last step, we display the current masters
	print STDERR "Reporting new writer(s) :\n";
	$selh->execute() or die "Unable to execute: $DBI::errstr\n";
	my @newhosts;
	while (my $res=$selh->fetchrow_hashref) {
		push (@newhosts, $res);
	}
	foreach (@newhosts) {
		my $s=$_;
		print "	$s->{'hostname'} $s->{'port'}\n";
	}
	return 0;
}


if(!caller) { exit(main(@ARGV)); }
