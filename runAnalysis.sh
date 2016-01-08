#!/bin/bash
#
# Start Hadoop firewall log analysis for a given HDFS input path
#

# Directories
HADOOP_BIN='/usr/bin'
HADOOP_CONTRIB='/usr/share/hadoop/contrib'
SCRIPTDIR="./"

# Hadoop variables
NUM_REDUCERS=4

# Make sure output dir exists
if [ ! -d "./output/" ]; then
  mkdir -p ./output/
fi

# Verify number of arguments
if [ $# -lt 1 ]
then
    echo "Usage: $0 <path> [<path> <path> ...]"
    echo "    Path must be a valid HDFS directory with firewall logs. Wildcards are allowed."
    echo " "
    echo "Examples (where /data is the HDFS base path for logfiles):"
    echo "    $0 /data/firewall1/*201307*      will process all logs for firewall1 for July 2013"
    echo "    $0 /data/firewall2/*20130[123]*  will process all logs for firewall2 for January, February and March 2013"
    echo "    $0 /data/*/*20130515*            will process the log for May 15th for all firewalls (or, all subdirectories under /data)"
    echo "Example with several paths:"
    echo "    $0 /data/firewall1/*20130[6-9]* /data/firewall1/*20131[0-2]*     will process logs for June through Desember for firewall1"
    echo " "
    echo "Use 'hadoop dfs -ls /data' to get a list of possible devices to choose from."
    exit 1
elif [ $# -ge 1 ]
then
    # Remove script name from argument list and use rest as input path
    shift 0
    COMBINEDPATH=$@
fi

# Start Hadoop job
$HADOOP_BIN/hadoop jar $HADOOP_CONTRIB/streaming/hadoop-streaming*.jar \
-Dmapred.job.name="Firewall Ruleset Analysis: Path $COMBINEDPATH" \
-Dmapred.reduce.tasks=$NUM_REDUCERS \
-Dmapred.job.priority=LOW \
-mapper  $SCRIPTDIR/mapper.py \
-reducer $SCRIPTDIR/connlist-reducer.py \
-file    $SCRIPTDIR/config.py \
-file    $SCRIPTDIR/lib/fw-regex/libfwregex.py \
-file    $SCRIPTDIR/firewallrule.py \
-file    $SCRIPTDIR/input/accesslists.db \
-file    $SCRIPTDIR/name-number-mappings.db \
-file    $SCRIPTDIR/mapper.py \
-file    $SCRIPTDIR/connlist-reducer.py \
-input   $COMBINEDPATH \
-output  output-`date +%Y%m%d-%H%M`_RulesetAnalysis &
