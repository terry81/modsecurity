#!/usr/bin/perl

# Copyright (C) 2013 Anatoliy Dimitrov
# website-security.info, tollodim@gmail.com
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# Description: This Perl script takes as an argument Apache's error log
# file which contains the ModSecurity output by default. It analyzes the
# log for the last 1 hour and does 2 things:
# - sends a mail containing the number of requests blocked per Ip +
# the number of triggered ModSecurity rules
# - blocks an IP if it has triggeredd more than 500 ModSecurity alerts
#
# Usage: The simplest usage is to run this script daily and set it as a 
# cron to run just before mid-nigth

use warnings;

# Define either the first argument as the Modsecurity Log or hardcode it (default)
# my $file = $ARGV['0'];
my $file = '/var/log/httpd/apache-error_log';

# Get the current date in the format 'Fri Feb 17'. This is necessary for log files
my $date = `date +"%a %b %d"`;
chomp($date);

# Open the log file for reading and prepare it for search
open INPUT, '<', $file or warn "Unable to open log file: $file!\n";
my @input_array=<INPUT>;
close(INPUT);
my $file_code=join("",@input_array);

my %attackers = ();
my %sec_ids = ();

my $search_pattern = '\['.$date . '.*\[client ([0-9|\.]*)\] ModSecurity.*\[id "([0-9]{6})"\]';

while ( $file_code =~ m/$search_pattern/g ) {
        $attackers{$1}++;
        $sec_ids{$2}++;
}

open(MAIL, "|/usr/sbin/sendmail -tv");

print MAIL "From: modsecurity-alerts\@example.org\n";
print MAIL "To: admins\@example.org\n";
print MAIL "Subject: Mod Security Stats\n\n";

print MAIL "Attackers:\n";
while ( ($k,$v) = each %attackers ) {
    print MAIL "$k => $v\n" if $v > 10;
    #If an attacker has more than 500 malicious hits block him
    if ($v > 500) {
        system("/sbin/iptables -I INPUT -s $k -p TCP --dport 80 -j DROP")
    }
}

print MAIL "\nModsecurity IDs:\n";
# This is useful because some of these IDs may turn out to be blocking legitimate requests. Analyze them and optionally whitelist these IDs.
while ( ($k,$v) = each %sec_ids ) {
    print MAIL "$k => $v\n" if $v > 10;
}

close(MAIL);
