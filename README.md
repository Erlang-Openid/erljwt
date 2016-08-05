Erlang JWT Library
=

JWT is a simple authorization token [format](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html) based on JSON. 
The library is based on work by Kato.im and was enhanced with tests, stylechecking and the RS256 algorithm. It now uses maps and the jsx library for JSON parsing/checking.

This library is used by the OpenId Connect client library oidcc.

## Smoke test example

Compilation
```shell
   make
   make eunit 
```

In Erlang shell:

    %% Create JWT token
    application:start(crypto).
    Key = <<"53F61451CAD6231FDCF6859C6D5B88C1EBD5DC38B9F7EBD990FADD4EB8EB9063">>.
    Claims = {[
        {user_id, <<"bob123">>},
        {user_name, <<"Bob">>}
    ]}.
    ExpirationSeconds = 86400,
    Token = erljwt:jwt(hs256, Claims, ExpirationSeconds, Key).

    %% Parse JWT token
    erljwt:parse_jwt(Token, Key).


You should get back the original claims Jterm, plus expiration claim:

    {[
        {<<"exp">>,1392607527},
        {<<"user_id">>,<<"bob123">>},
        {<<"user_name">>,<<"Bob">>}
    ]}

