#!/usr/bin/perl
use strict;
use warnings;
use DBI;
use DBD::mysql;


use Getopt::Long qw(:config permute no_ignore_case);


my %opts;


sub main {
  @ARGV = @_;
  $opts{'user'} = $ENV{"DBI_USER"} || "";
  $opts{'password'} = $ENV{"MYSQL_PWD"} || "";
  $opts{'host'} = $ENV{"MYSQL_HOST"} || "127.0.0.1";
  $opts{'port'} = $ENV{"MYSQL_TCP_PORT"} || 6032;
  GetOptions(\%opts,
   'user|u=s',
   'password|p=s',
   'host|h=s',
   'port|P=i',
  );
	my $dbn="dbi:mysql:main:".$opts{'host'}.":".$opts{'port'};
	my $dbh=DBI->connect($dbn, $opts{'user'}, $opts{'password'}) or die "Unable to connect: $DBI::errstr\n";
	my $query="SELECT * FROM runtime_global_variables";
	my $selh=$dbh->prepare($query) or die "Unable to prepare: $DBI::errstr\n";
	$selh->execute() or die "Unable to execute: $DBI::errstr\n";
	my %data;
	while (my $res=$selh->fetchrow_hashref) {
		$data{$res->{'variable_name'}}=$res->{'variable_value'}
	}

#	printf "ProxySQL is running with: $data{'mysql-threads'} threads\n";

	my $warns=0;
	if ($data{'mysql-poll_timeout'}*2 > $data{'mysql-ping_interval_server_msec'}) {
		printf "WARN: mysql-ping_interval_server_msec ($data{'mysql-ping_interval_server_msec'}) is too small compared to mysql-poll_timeout ($data{'mysql-poll_timeout'})\n";
		$warns+=1;
	}
	if ($data{'mysql-ping_interval_server_msec'} < $data{'mysql-ping_timeout_server'}*5) {
		printf "WARN: mysql-ping_interval_server_msec ($data{'mysql-ping_interval_server_msec'}) is too small compared to mysql-ping_timeout_server ($data{'mysql-ping_timeout_server'})\n";
		$warns+=1;
	}
	if ($data{'mysql-monitor_ping_interval'} < $data{'mysql-monitor_ping_timeout'}*5) {
		printf "WARN: mysql-monitor_ping_interval ($data{'mysql-monitor_ping_interval'}) is too small compared to mysql-monitor_ping_timeout ($data{'mysql-monitor_ping_timeout'})\n";
		$warns+=1;
	}
	if ($data{'mysql-monitor_read_only_interval'} < $data{'mysql-monitor_read_only_timeout'}*5) {
		printf "WARN: mysql-monitor_read_only_interval ($data{'mysql-monitor_read_only_interval'}) is too small compared to mysql-monitor_read_only_timeout ($data{'mysql-monitor_read_only_timeout'})\n";
		$warns+=1;
	}
	if ($data{'mysql-monitor_replication_lag_interval'} < $data{'mysql-monitor_replication_lag_timeout'}*5) {
		printf "WARN: mysql-monitor_replication_lag_interval ($data{'mysql-monitor_replication_lag_interval'}) is too small compared to mysql-monitor_replication_lag_timeout ($data{'mysql-monitor_replication_lag_timeout'})\n";
		$warns+=1;
	}
	if ($data{'mysql-connect_timeout_server_max'} < $data{'mysql-connect_timeout_server'}*2) {
		printf "WARN: mysql-connect_timeout_server_max ($data{'mysql-connect_timeout_server_max'}) is too small compared to mysql-connect_timeout_server ($data{'mysql-connect_timeout_server'})\n";
		$warns+=1;
	}

	printf "Check variables completed with $warns warnings.\n";

	return 0;
}

if(!caller) { exit(main(@ARGV)); }
