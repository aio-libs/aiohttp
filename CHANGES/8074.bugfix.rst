Fixed an unhandled exception in the Python HTTP parser on header lines starting with a colon -- by :user:`pajod`.

Invalid request lines with anything but a dot between the HTTP major and minor version are now rejected. Invalid header field names containing question mark or slash are now rejected. Such requests are incompatible with :rfc:`9110#section-5.6.2` and are not known to be of any legitimate use.

(BACKWARD INCOMPATIBLE)
