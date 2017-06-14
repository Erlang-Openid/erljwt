-module(erljwt_test).
-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

-define(OCT_JWK, #{ kty => <<"oct">>, k => <<"my secret key">>} ).

-define(RSA_JWK, #{ kty => <<"RSA">>,
                    n => <<"1AMRuJC7Wm2zMl-XaOmoToKqXqZdrYlu0LCdjWKmi3d3gP5vu1zipN65Y0biJp4OqFs8YnuGfeFK4Ye40TszcOt7z7SW9u7nqNKhZskNQYb460oOYuvEXTNJQKSvz_wAtYXgnrvMgP7Mf4ujO5nViEMiKYpkMGeFVaxFUCQhiN7b6OLseTI25sDGGPyBH125Myo1FdoKhonIiYFNkXZC7pKlRm3RFhyVEQGnEezNg4DnvXqZnpPluIN4PiXwi7Ped0VKpNQmdo-3tGmE9jjYirVIGCxhstEKTmaCexL8Li8HuaEOSf6KwaJbOcqI8pEFzECr9hGkI5sJ12Hnua89yw">>,
                    e => <<"AQAB">>,
                    d => <<"ZVo6RINcLXS37-Lm3Q6mmTG6BJl_uxAyW62zA_4fJBkulgoMnANhjfOzqJQgVNnGpBFJosLunorvYzWg0tV8WAUbIUZxzQaU1I4s_pgqsCK4KLM0gXG4Y926rR6Ntd4A8MZZhUi-EQS9-lNk6381J3kAgd9Y2hMDGNvMHu3G4kjYfsWq-KboZmJG8k4DnEPwxOC-6hgcXUXXxQTkymrlLqY7cty9nN4QICLXFij3KFDJqft87XCPwJ4yPKpfTJEdO5LVmUQ11C0lfpPoND3_F2yd3yXmyIJfUj-_1gSjvvL2VMLUOzwAU8XcSqrMIpFs2YjNkxtnYok0yBS5ZyPdwQ">>
                  }).

-define(ES256_JWK, #{ kty => <<"EC">>, crv => <<"P-256">>,
                      x => <<"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU">>,
                      y => <<"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a1">>,
                      d => <<"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI">>
                    }).

-define(ES384_JWK, #{ kty => <<"EC">>, crv => <<"P-384">>,
                      x => <<"kp3m6F7Zo349rSH2bUNSY86bGSGWzDOH-TUhklgTehJC1HnhHw7aRWZEYDQr93dY">>,
                      y => <<"bxgu3eepDWqg0HmpelIUWwbZS8ULD3CQBiOlcmJEW_dltj6VVgu-hXyv0FbDdw_H">>,
                      d => <<"c123iprPrEesbmTdtb2pR82vU2GBTlKWrcofXHzOmHeEP5ic8vy0q8bMCchoyZ9U">>
                    }).

-define(ES512_JWK, #{ kty => <<"EC">>, crv => <<"P-521">>,
                      x => <<"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk">>,
                      y => <<"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2">>,
                      d => <<"AY5pb7A0UFiB3RELSD64fTLOSV_jazdF7fLYyuTw8lOfRhWg6Y6rUrPAxerEzgdRhajnu0ferB0d53vM9mE15j2C">>
                    }).

-define(JWS, #{keys => [?RSA_JWK, ?OCT_JWK, ?ES256_JWK, ?ES384_JWK, ?ES512_JWK]}).



rs256_verification_test() ->
    IdToken =
    <<"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0NjA2MzE4MjEsImlzcyI6Imh0dHBzOi8vcHJvdG9uLnNjYy5raXQuZWR1Iiwic3ViIjoiam9lIiwiYXVkIjoiMTIzIiwiaWF0IjoxNDYwNjMxNTIxLCJhdXRoX3RpbWUiOjE0NjA2MzE1MjF9.nUKMCw_ppksTD49qWR7hs_FTNnVu2qaohnh67jANI9Cje7gaFi2puIsXbC_i0HoFnppR5mA_3B20f7X8O3UF3ZrgYyfjjAq5U3HeZ-Tx6xEd2EcJ-gfpVnoAJPa46Lx77NmApUyTAazXj8kjzgkh58_QDxujG13g55ckRG9qJfK3bX_h0ec07ARJWQSg_Zh8Q3lFB_iIbSDXOYegSAHhIpTxmuTA-qmPn3ySGIRirQt_-niek0-wyy5PAsxSU9lc42QIG7qdMLhvXsq5j52kPO9DA3vJNpGTloJ8H1AoE-ES8HpXH3RhRMe3cdiVyK2vTsPbRc0-GxkRZMKaocyOPQ">>,
    expired = erljwt:check_sig(IdToken, [rs256], ?JWS),
    ok.

es256_verification_test() ->
    JWT = <<"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q">>,
    io:format("~p~n", [erljwt:to_map(JWT)]),
    expired = erljwt:validate(JWT, [es256], #{},  ?JWS),
    ok.


none_roundtrip_test() ->
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    JWT = erljwt:create(none, Claims, 10, undefined),
    Result = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS),
    true = valid_claims(Claims, Result).

hs256_roundtrip_test() ->
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    JWT = erljwt:create(hs256,Claims, 10, ?OCT_JWK),
    Result = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS),
    true = valid_claims(Claims, Result).

hs384_roundtrip_test() ->
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    JWT = erljwt:create(hs384,Claims, 10, ?OCT_JWK),
    Result = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS),
    true = valid_claims(Claims, Result).

hs512_roundtrip_test() ->
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    JWT = erljwt:create(hs512,Claims, 10, ?OCT_JWK),
    Result = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS),
    true = valid_claims(Claims, Result).

rs256_roundtrip_test() ->
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    JWT = erljwt:create(rs256, Claims, 10, ?RSA_JWK),
    Result = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS),
    true = valid_claims(Claims, Result).

rs384_roundtrip_test() ->
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    JWT = erljwt:create(rs384, Claims, 10, ?RSA_JWK),
    Result = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS),
    true = valid_claims(Claims, Result).

rs512_roundtrip_test() ->
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    JWT = erljwt:create(rs512, Claims, 10, ?RSA_JWK),
    Result = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS),
    true = valid_claims(Claims, Result).

es256_roundtrip_test() ->
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    JWT = erljwt:create(es256, Claims, 10, ?ES256_JWK),
    Map = erljwt:to_map(JWT),
    Sig = maps:get(signature, Map),
    io:format("created jwt: ~p~n", [Map]),
    io:format("signature length: ~p~n", [byte_size(base64url:decode(Sig))]),
    Result = erljwt:validate(JWT, [es256], #{}, ?JWS),
    true = valid_claims(Claims, Result).

es384_roundtrip_test() ->
    %% {PubKey, PrivKey} = crypto:generate_key(ecdh, secp384r1),
    %% Bits = 4* (byte_size(PubKey) - 1),
    %% << 4:8, X:Bits, Y:Bits >> = PubKey,
    %% Key = #{ crv => <<"P-384">>, x => base64url:encode(binary:encode_unsigned(X)),
    %%          y => base64url:encode(binary:encode_unsigned(Y)), d => base64url:encode(PrivKey)},
    %% io:format("key: ~p~n", [Key]),
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    JWT = erljwt:create(es384, Claims, 10, ?ES384_JWK),
    io:format("created jwt: ~p~n", [erljwt:to_map(JWT)]),
    Result = erljwt:validate(JWT, [es384], #{}, ?JWS),
    true = valid_claims(Claims, Result).

es512_roundtrip_test() ->
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    JWT = erljwt:create(es512, Claims, 10, ?ES512_JWK),
    io:format("created jwt: ~p~n", [erljwt:to_map(JWT)]),
    Result = erljwt:validate(JWT, [es512], #{}, ?JWS),
    true = valid_claims(Claims, Result).

unsupported_alg_test() ->
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    alg_not_supported = erljwt:create(xy21,Claims, 10, ?OCT_JWK),
    application:unset_env(erljwt, add_iat).

to_map_test() ->
    Claims = claims(),
    JWT = erljwt:create(none, Claims, 10, undefined),
    Result = erljwt:to_map(JWT),
    Result = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS),
    true = valid_claims(Claims, Result).

exp_test() ->
    application:set_env(erljwt, add_iat, true),
    Claims = claims(),
    JWT = erljwt:create(rs256, Claims, ?RSA_JWK),
    Result = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS),
    true = valid_claims(Claims, Result).

exp_fail_test() ->
    application:set_env(erljwt, add_iat, true),
    Now = erlang:system_time(seconds),
    Claims = maps:merge(#{exp=> (Now -1)}, claims()),
    JWT = erljwt:create(rs256, Claims, ?RSA_JWK),
    expired = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS).

iat_fail_test() ->
    application:set_env(erljwt, add_iat, true),
    Now = erlang:system_time(seconds),
    Claims = maps:merge(#{iat => (Now + 10)}, claims()),
    JWT = erljwt:create(rs256, Claims, 10, ?RSA_JWK),
    not_issued_in_past = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS).

iat_test() ->
    application:set_env(erljwt, add_iat, true),
    Claims = claims(),
    JWT = erljwt:create(rs256, Claims, 10, ?RSA_JWK),
    timer:sleep(2000),
    Result = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS),
    true = valid_claims(Claims, Result).

nbf_fail_test() ->
    application:set_env(erljwt, add_iat, true),
    Now = erlang:system_time(seconds),
    Claims = maps:merge(#{nbf => (Now + 1)}, claims()),
    JWT = erljwt:create(rs256, Claims, 10, ?RSA_JWK),
    not_yet_valid = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS).

nbf_test() ->
    application:set_env(erljwt, add_iat, true),
    Now = erlang:system_time(seconds),
    Claims = maps:merge(#{nbf => (Now + 1)}, claims()),
    JWT = erljwt:create(rs256, Claims, 10, ?RSA_JWK),
    timer:sleep(2000),
    Result = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS),
    true = valid_claims(Claims, Result).


algo_test() ->
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    JWT = erljwt:create(rs256, Claims, 10, ?RSA_JWK),
    Result = erljwt:validate(JWT, [rs256], Claims, ?JWS),
    true = valid_claims(Claims, Result).

algo_fail_test() ->
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    JWT = erljwt:create(hs256,Claims, 10, ?OCT_JWK),
    algo_not_allowed = erljwt:check_sig(JWT, [rs256], ?JWS).

garbage_test() ->
    invalid = erljwt:validate(<<"abc">>, erljwt:algorithms(), #{}, #{keys => []}),
    ok.

claims() ->
    #{iss => <<"me">>,
      sub => <<"789049">>,
      aud => <<"someone">>,
      azp => <<"thesameone">>,
      nonce => <<"WwiTGOVNCSTn6tXFp8iW_wsugAp1AGm-81VJ9n4oy7Bauq0xTKg">>}.

valid_claims(OrgClaims, #{claims := ExtClaims}) when is_map(ExtClaims) ->
    io:format("org claims: ~p~n~next claims: ~p~n~n", [OrgClaims, ExtClaims]),
    io:format("add iat ~p~n",[add_iat()]),
    IatOk = (add_iat() == maps:is_key(iat, ExtClaims)),
    SameClaims =
        (ExtClaims == maps:merge(OrgClaims, maps:with([exp, iat], ExtClaims))),
    application:unset_env(erljwt, add_iat),
    io:format("iat ok: ~p, same claims: ~p~n", [IatOk, SameClaims]),
    IatOk and SameClaims;
valid_claims(OrgClaims, Result)  ->
    io:format("no maps:~norg claims ~p~n~nresult: ~p~n", [OrgClaims, Result]),
    application:unset_env(erljwt, add_iat),
    false.


add_iat() ->
    application:get_env(erljwt, add_iat, true).
