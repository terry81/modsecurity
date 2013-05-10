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

