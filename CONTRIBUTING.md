# Contributing

For the private preview, open an issue with the smallest reproducible example. Use synthetic sessions when reporting collection or attribution problems. Include the operating system, runtime and the step you expected to see.

To test a change with Python 3.12+, install the pinned browser once and run:

```sh
python3 deploy/fetch_test_browser.py
python3 -m unittest discover -s tests
python3 -m unittest discover -s integrations/tests -t .
```

The DOM test additionally needs Node and jsdom 26 available through NODE_PATH. The optional live OpenBot test requires a channel you control; set TEST_OPENBOT_CHANNEL_ID to opt in. Other collaboration tests use disposable fixture databases.

For security reports, contact a repository maintainer privately. Include a sanitized reproduction and the affected version. Keep real credentials, session records and private files out of issues.
