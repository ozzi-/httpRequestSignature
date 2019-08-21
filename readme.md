# Siging HTTP requests
This is a demonstration on how HTTP(s) requests can be signed.
The key material is creating using Curve25519 (https://en.wikipedia.org/wiki/Curve25519).

The following steps are required to create and validate the signed request:
![flow](https://i.imgur.com/rUNnuXP.png)

**Note:** This demo does not cover the public key transfer to the server

## Example Output of the Demo Code
```
1 - requestJSON
***************
{
    "__nonce__": "tC7raPJtLvlkT9QF",
    "__timestamp__": 1566387813,
    "uri": "my.url.ch/resources/17",
    "method": "PUT",
    "body": "c29tZSBib2R5"
}


2 - requestJSONCanonized
************************
{"__nonce__":"tC7raPJtLvlkT9QF","__timestamp__":1566387813,"body":"c29tZSBib2R5","method":"PUT","uri":"my.url.ch/resources/17"}


3 - signedRequest
*****************
r/qP0tdnAO5zcE4wd3wjh7GA6YDv6O7FaJbCQwzBqHBOrkOYgCny5I2V1N0et7BXXZk0AluD10hG6ZRvsJoOBw==


4 - signatureJSON
*****************
{
    "__nonce__": "tC7raPJtLvlkT9QF",
    "__timestamp__": 1566387813,
    "signature": "r/qP0tdnAO5zcE4wd3wjh7GA6YDv6O7FaJbCQwzBqHBOrkOYgCny5I2V1N0et7BXXZk0AluD10hG6ZRvsJoOBw=="
}


5 - header
**********
X-HTTP-SIGNATURE: ewogICAgIl9fbm9uY2VfXyI6ICJ0QzdyYVBKdEx2bGtUOVFGIiwKICAgICJfX3RpbWVzdGFtcF9fIjogMTU2NjM4NzgxMywKICAgICJzaWduYXR1cmUiOiAici9xUDB0ZG5BTzV6Y0U0d2Qzd2poN0dBNllEdjZPN0ZhSmJDUXd6QnFIQk9ya09ZZ0NueTVJMlYxTjBldDdCWFhaazBBbHVEMTBoRzZaUnZzSm9PQnc9PSIKfQ==


***** CONTEXT CHANGE - SERVER SIDE *****


6 - requestJSONServer
*********************
{"__nonce__":"tC7raPJtLvlkT9QF","__timestamp__":1566387813,"body":"c29tZSBib2R5","method":"PUT","uri":"my.url.ch/resources/17"}


7 - * Signature validation *
****************************
Valid? true


8 - *Replay nonce check*
************************
Nonce replay works? false
```
