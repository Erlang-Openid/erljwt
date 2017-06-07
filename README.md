Erlang JWT Library
=
erljwt is a easy to use json web token [JWT] parsing and minting library.
JWT is a simple authorization token [RFC7519](https://www.rfc-editor.org/rfc/rfc7519.txt) based on JSON.

erljwt uses the jsone library for json parsing.

supported algorithm
 - none
 - RS256
 - RS384
 - RS512
 - HS256
 - HS384
 - HS512

## Smoke test example

Compilation
```shell
   make
   make eunit
```

In Erlang shell:

```
    %% Create JWT token
    application:start(crypto).
    Key = <<"53F61451CAD6231FDCF6859C6D5B88C1EBD5DC38B9F7EBD990FADD4EB8EB9063">>.
    Claims = {[
        {user_id, <<"bob123">>},
        {user_name, <<"Bob">>}
    ]}.
    ExpirationSeconds = 86400,
    Token = erljwt:create(hs256, Claims, ExpirationSeconds, Key).

    %% Parse JWT token
    erljwt:parse(Token, Key).
```

You should get back the original claims ,plus expiration claim and the header and signature:

```
    #{ claims =>
        #{<<"exp">> => 1392607527,
          <<"user_id">> => <<"bob123">>,
          <<"user_name">> => <<"Bob">>
         },
       header => #{...},
       signature => <<"lnmmaen....">>
    }
```
