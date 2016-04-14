@load ./

##! Create a bulk connection log for when a connection is shunted.

event bro_init()
	{
	Log::add_filter(Conn::LOG, [
		$name = "conn-bulk",
		$path = "conn_bulk",
		$pred(rec: Conn::Info) = {
			return rec$bulk;
		}]);
	}