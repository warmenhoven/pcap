This implements an extremely basic TCP/IP stack, in user-space (mostly), from a phony address.
You'll need to read the source to see how to use it.
In addition to doing basic things like ping and reading/writing data, it also has a simple reimplementation of [sting](http://www.cs.ucsd.edu/~savage/sting/), which measures one-way packet loss.
It's also a good starting point for you if you'd like to do something real. Depends on libpcap and libnet 1.1.
