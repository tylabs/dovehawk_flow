module dovehawk_flow;

export { 

	global APIKEY = "XXXX"; 

	global dns_report_url = "https://XXXX.amazonaws.com/default/XXX?feed=pdns&toolkey=" + APIKEY;

	## How often flow should be reported.
	const logging_interval = 10min &redef;

}
