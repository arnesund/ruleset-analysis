RulesetAnalysis
===============

Analyze firewall traffic logs to determine which firewall rules are in use and what traffic matched those rules. A typical use-case is to replace a generic rule with more specific rules better matching the traffic.

Currently Cisco ASA/FWSM and Fortinet FortiGate firewalls are supported. There is a separate preprocessor for each platform, and to create support for a new platform or rule syntax all that's needed is to add a new preprocessor for it. The analysis running on Hadoop is vendor-agnostic and only depends on rules and rulesets stored in an access-list database ("input/accesslists.db" in Python Shelve format).

## Walkthrough of the usage

[Read this blog post](http://arnesund.com/2015/01/04/how-to-analyze-a-firewall-ruleset-with-hadoop/) for examples and a walkthrough of the usage.

## Prerequisites

To be able to run the analysis as a Hadoop job, you need:

 * Firewall config file as a text file (for example config file collected by RANCID)
 * Firewall log files uploaded to HDFS
 * Hadoop tools installed, to be able to submit jobs to a cluster
   * You need the **hadoop** binary and the path to the **hadoop-streaming** jar file
   * Test availability of tools with **hadoop version** in a terminal
 * Python module 'ciscoconfparse' installed (only on host performing preprocessing of firewall config)
   * Install with 'easy_install -U ciscoconfparse' or get tarball from https://pypi.python.org/pypi/ciscoconfparse
 * Python module 'IPy' installed on all cluster nodes
   * Install with 'easy_install -U IPy' or get tarball from https://pypi.python.org/pypi/IPy
   * Ask your cluster administrator for help if you don't have access to installing packages on the cluster nodes
 * Git submodule 'fw-regex' checked out after checking out this repo: 'git submodule init && git submodule update'

## Quick Start Guide

Before launching your first analysis, first make sure all prerequisites listed above are met.

To perform a ruleset-analysis, you need to complete the following steps:
 1. Preprocess firewall config to create a database of accesslists: `./preprosess_access_lists.py -f <INSERT_FILE_PATH>` with the path to the firewall config file as the only argument
 2. Launch the job on the cluster by running `./runAnalysis.sh <INSERT_HDFS_PATH>` with the HDFS path to log files (supplying more than one path is supported)
 3. Copy the result files to local disk:
```mkdir output;
outputdir="<INSERT_OUTPUT_PATH_FROM_JOB_OUTPUT>";
hadoop dfs -getmerge $outputdir output/$outputdir```
 4. Run postprocessing script to generate the ruleset report:
```./postprocess_ruleset_analysis.py -f output/$outputdir > output/$outputdir-postprocessed.log```
 5. Display results: `less output/$outputdir-postprocessed.log`

