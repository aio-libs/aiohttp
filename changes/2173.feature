Fix parsing the Forwarded header.

* commas and semicolons are allowed inside quoted-strings;

* empty forwarded-pairs (as in for=_1;;by=_2) are allowed;

* non-standard parameters are allowed (although this alone could be
  easily done in the previous parser).
