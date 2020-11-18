Logging
=======

You can always enable debug logging when you run into issues in your code::

  import logging
  import sys
  log = logging.getLogger('authlib')
  log.addHandler(logging.StreamHandler(sys.stdout))
  log.setLevel(logging.DEBUG)

We are still designing the logging system. (TBD)
