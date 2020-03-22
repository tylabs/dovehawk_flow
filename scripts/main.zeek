# Dovehawk.io Anonymized Outbound Flow Module v1.1.0 2020 03 21

@load base/utils/site
@load base/frameworks/sumstats
@load base/utils/directions-and-hosts

@load ../config

module dovehawk_flow;

export {


	## The log ID.
	redef enum Log::ID += { LOG };

	type Info: record {
		## Timestamp of when the data was finalized.
		ts:           time             &log;

		## Length of time that this Top measurement represents.
		ts_delta:     interval         &log;

		## The top queries being performed.
		aresp_h:  string &log;

		## The estimated counts of each of the top queries.
		asum:   double  &log;

	};

	global log_flow: event(rec: Info);
	global out: table[string] of double;

}

function send_json(json: string) {
    local post_data = json;

    local request: ActiveHTTP::Request = [
	$url=dovehawk_flow::flow_report_url,
	$method="POST",
	$client_data=post_data,
	$addl_curl_args = fmt("--header \"Content-Type: application/json\" --header \"Accept: application/json\"")
    ];
	
    when ( local resp = ActiveHTTP::request(request) ) {
		
		if (resp$code == 200) {
			print fmt("  DoveHawk Flow Reporting Sent ===> %s", resp$body);
		} else {
			print fmt("  DoveHawk Flow Reporting FAILED ===> %s", resp);
		}
    }
	
}

event zeek_init() &priority=5
	{

	local rec: dovehawk_flow::Info;

	Log::create_stream(dovehawk_flow::LOG, [$columns=Info, $path="flow", $ev=log_flow]);

	local r1 = SumStats::Reducer($stream="flow-conn", $apply=set(SumStats::SUM));


	SumStats::create([$name="find-flow-conn",
	                  $epoch=logging_interval,
	                  $reducers=set(r1),
	                  $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
	                  	{

	                  		local r = result["flow-conn"];
					#print fmt(" %s aggregated %g bytes, %s",key$str, r$sum, ts);
					out[key$str] = r$sum;
	                  		Log::write(dovehawk_flow::LOG, [$ts=ts, $ts_delta=logging_interval, $aresp_h=key$str, $asum = r$sum]);

	                  	},
  			   $epoch_finished(ts: time) =
                        	{
					local c = |out|;
					if (c > 0) {
						print fmt("DoveHawk %s: %d flow records to send", ts, c);
						print fmt("DoveHawk %s sending flow records", ts);
						send_json(to_json(out));
						#print to_json(out);
					}

					# reset storage
					out = table();
					
                        	}
	                 ]);

		print fmt("DoveHawk Flow Reporting Period %s", logging_interval);


	}



event Conn::log_conn(rec: Conn::Info)
{

	if (rec?$resp_bytes && rec?$orig_bytes )
	{
        	local total_bytes = rec$resp_bytes + rec$orig_bytes;
        	local ratio_bytes: int = rec$resp_bytes - rec$orig_bytes;
		if (!Site::is_local_addr(rec$id$resp_h)) {

			#could limit on total_byte or interval_to_double(rec$duration)
        		#print fmt("%s:%s %d+%d=%d [%s]", rec$id$resp_h, rec$id$resp_p, rec$orig_bytes, rec$resp_bytes, total_bytes, ratio_bytes);
			#print fmt("  duration: %gs, orig_pkts %d, resp_pkts %d",rec$duration, rec$orig_pkts, rec$resp_pkts);
            		SumStats::observe("flow-conn", [$str=fmt("%s",rec$id$resp_h)], [$num=rec$orig_bytes]);

		# special case for users with their own internet blocks
		} else if (!Site::is_local_addr(rec$id$orig_h)) {
       			#print fmt("DIRECT IN %s:%s %d+%d=%d [%s]", rec$id$resp_h, rec$id$resp_p, rec$orig_bytes, rec$resp_bytes, total_bytes, ratio_bytes);
			#print fmt("  duration: %gs, orig_pkts %d, resp_pkts %d",rec$duration, rec$orig_pkts, rec$resp_pkts);
 			
            		SumStats::observe("flow-conn", [$str=fmt("%s",rec$id$orig_h)], [$num=rec$resp_bytes]);

		}
	}
}


