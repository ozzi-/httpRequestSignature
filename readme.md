# Signing HTTP requests
This is a demonstration on how HTTP(s) requests can be signed.
The key material is creating using Curve25519 (https://en.wikipedia.org/wiki/Curve25519).

Note: This demo code does not show how the public keys will be transferred to and stored on the server side

The following steps are required to create and validate the signed request:
![flow](https://i.imgur.com/UJgsZbo.png)

## Example Output of the Demo Code
```
1 - requestJSON
***************
{
    "__nonce__": "2lrxBZJo7hWrjUaW",
    "__timestamp__": 1571142490,
    "uri": "http://some.url.ch",
    "method": "PUT",
    "body": "c29tZSBib2R5"
}


2 - requestJSONCanonized
************************
{"__nonce__":"2lrxBZJo7hWrjUaW","__timestamp__":1571142490,"body":"c29tZSBib2R5","method":"PUT","uri":"http://some.url.ch"}


3 - signedRequest
*****************
wGkhqejplndhCsvLNWOxNbZyAr/XeoBrPkpDE3eJv9M7qu2xXu4UPclqIv4xqc0Duk99f7jziSM1JvPna6ivBQ==


4 - signatureJSON
*****************
{"__nonce__":"2lrxBZJo7hWrjUaW","__timestamp__":1571142490,"signature":"wGkhqejplndhCsvLNWOxNbZyAr/XeoBrPkpDE3eJv9M7qu2xXu4UPclqIv4xqc0Duk99f7jziSM1JvPna6ivBQ=="}


5 - header
**********
X-HTTP-SIGNATURE: eyJfX25vbmNlX18iOiIybHJ4QlpKbzdoV3JqVWFXIiwiX190aW1lc3RhbXBfXyI6MTU3MTE0MjQ5MCwic2lnbmF0dXJlIjoid0draHFlanBsbmRoQ3N2TE5XT3hOYlp5QXIvWGVvQnJQa3BERTNlSnY5TTdxdTJ4WHU0VVBjbHFJdjR4cWMwRHVrOTlmN2p6aVNNMUp2UG5hNml2QlE9PSJ9


***** CONTEXT CHANGE - SERVER SIDE *****


6 - requestJSONServer
*********************
{"__nonce__":"2lrxBZJo7hWrjUaW","__timestamp__":1571142490,"body":"c29tZSBib2R5","method":"PUT","uri":"http://some.url.ch"}


7 - * Signature validation *
****************************
Valid? true


8 - * Replay nonce check *
**************************
Nonce replay works? false
```
