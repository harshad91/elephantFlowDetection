# elephantFlowDetection

A network flow can be categorized as an elephant when it is long lasting and bandwidth demanding. Other short lived flows are termed as mice flows. Set of elephant flows, even if it is less in number can cause network congestion and affect other latency sensitive mice flows. In order to avoid congestion, we need to identify the elephant flow and apply congestion avoidance or traffic engineering strategies like rerouting a flow to a new path or separate paths for mice and elephant etc.

The capabilities of netfilter_queue library can be exploited by the hosts to tag the elephant flow packets on host. SDN controller can calculate and install the best route for these tagged flows.
