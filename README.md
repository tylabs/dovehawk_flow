# Dovehawk.io Anonymized Outgoing Flow Collector Module for Zeek

This module collects outgoing flow counts to external IPs across an entire Cluster or Standalone Zeek instance.  The local source IPs are not tracked and SUMSTATS is used to sum multiple requests over a specified time period anonymizing and grouping the requests across the entire network.

Local hostnames are stripped to further anonymize the data for external sharing.

![Sticker 1](https://dovehawk.io/images/dovehawk_sticker1.png "Sticker 1") ![Sticker 2](https://dovehawk.io/images/dovehawk_sticker2.png "Sticker 2")

## Screencaps

### DoveHawk Flow Reported

![Dovehawk Flow Reports](https://dovehawk.io/images/dovehawk_flow.png "Dovehawk Flow")


### DoveHawk flow.log Local Log

![Dovehawk Flow Log](https://dovehawk.io/images/flowlog.png "Dovehawk Flow Log")


## Requirements

Zeek > 3.0

Curl command line version used by ActiveHTTP


## Database

See [dovehawk_lambda](https://github.com/tylabs/dovehawk_lambda) for an AWS Lambda serverless function to store reporting in RDS Aurora.


## Contact

Tyler McLellan [@tylabs](https://twitter.com/tylabs)

