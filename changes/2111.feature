Added support for throttling DNS request, avoiding the requests saturation
when there is a miss in the DNS cache and many requests getting into the
connector at the same time.
