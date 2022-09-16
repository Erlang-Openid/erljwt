Erlang JWT Library
==================

erljwt is a easy to use json web token [JWT] parsing and minting library.
JWT is a simple authorization token [RFC7519](https://www.rfc-editor.org/rfc/rfc7519.txt) based on JSON.

erljwt uses the jsone library for json parsing.

supported algorithm (the atom to use)
 - none (none)
 - RS256 (rs256)
 - RS384 (rs384)
 - RS512 (rs512)
 - HS256 (hs256)
 - HS384 (hs384)
 - HS512 (hs512)
 - ES256 (es256)
 - ES384 (es384)
 - ES512 (es512)

## Minimal Example

Compilation
```shell
   make
   make eunit
```

In Erlang shell (start using `./rebar3 shell`):
```erlang
    %% Create JWT token
    application:start(crypto).
    Key = #{
        kty => <<"oct">>,
        k => <<"53F61451CAD6231FDCF6859C6D5B88C1EBD5DC38B9F7EBD990FADD4EB8EB9063">>
    }.
    Claims = #{
        user_id => <<"bob123">>,
        user_name => <<"Bob">>
    }.
    ExpirationSeconds = 86400.
    Token = erljwt:create(hs256, Claims, ExpirationSeconds, Key).

    %% validate JWT token
    erljwt:validate(Token, [hs256], #{}, Key).
```

You get back the original claims, plus expiration claim and the header and signature:

```erlang
{ok,
    #{ claims =>
        #{<<"exp">> => 1392607527,
          <<"user_id">> => <<"bob123">>,
          <<"user_name">> => <<"Bob">>
         },
       header => #{...},
       signature => <<"lnmmaen....">>
    }
}
```

## Configuration

In checking expiration and not-before timestamps there is an allowed clock difference.
This fixes the problem that servers might not have synchronized clocks.

Per default the allowed difference is 300 seconds (5 minutes).

This can be changed via the application env key `clock_skew`. The current allowed
clock skew can be requested with `erljwt:clock_skew()`.
