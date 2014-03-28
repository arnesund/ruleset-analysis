RulesetAnalysis
===============

Analyze firewall traffic logs to determine which firewall rules are in use and what traffic matched those rules. A typical use-case is to replace a generic rule with more specific rules better matching the traffic.

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

## Quick start guide

Before launching your first analysis, first make sure all prerequisites listed above are met.

To perform a ruleset-analysis, you need to complete the following steps:
 1. Preprocess firewall config to create a database of accesslists
 2. Launch the job on the cluster by running **runAnalysis.sh** with the HDFS path to log files as the only argument
 3. Copy the result files to local disk
 4. Run postprocessing script to generate the ruleset report

A sample command set for these steps would be:

```
# 1. Preprocess
./preprosess_access_lists.py -f <path_to_firewall_config_file>
# 2. Launch job
./runAnalysis.sh <HDFS_path_to_firewall_log_files>
# 3. Copy results to local disk
mkdir output
OUTPUTDIR="<reported_output_dir_name_from_job_output>"
hadoop dfs -getmerge $OUTPUTDIR output/$OUTPUTDIR
# 4. Postprocess and view results
./postprocess_ruleset_analysis.py -f output/$OUTPUTDIR > output/$OUTPUTDIR-postprocessed.log
less output/$OUTPUTDIR-postprocessed.log
```
