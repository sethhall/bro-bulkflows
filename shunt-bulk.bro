@load ./bulk-flows
@load policy/frameworks/packet-filter/shunt

event BulkFlows::detected(c: connection, is_orig: bool)
	{
	PacketFilter::shunt_conn(c$id);
	}