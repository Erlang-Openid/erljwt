-module(erljwt_test).
-include_lib("eunit/include/eunit.hrl").

-define(OCT_JWK, #{ kty => <<"oct">>, k => <<"my secret key">>} ).

-define(RSA_JWK, #{ kty => <<"RSA">>,
                    n => <<"1AMRuJC7Wm2zMl-XaOmoToKqXqZdrYlu0LCdjWKmi3d3gP5vu1zipN65Y0biJp4OqFs8YnuGfeFK4Ye40TszcOt7z7SW9u7nqNKhZskNQYb460oOYuvEXTNJQKSvz_wAtYXgnrvMgP7Mf4ujO5nViEMiKYpkMGeFVaxFUCQhiN7b6OLseTI25sDGGPyBH125Myo1FdoKhonIiYFNkXZC7pKlRm3RFhyVEQGnEezNg4DnvXqZnpPluIN4PiXwi7Ped0VKpNQmdo-3tGmE9jjYirVIGCxhstEKTmaCexL8Li8HuaEOSf6KwaJbOcqI8pEFzECr9hGkI5sJ12Hnua89yw">>,
                    e => <<"AQAB">>,
                    d => <<"ZVo6RINcLXS37-Lm3Q6mmTG6BJl_uxAyW62zA_4fJBkulgoMnANhjfOzqJQgVNnGpBFJosLunorvYzWg0tV8WAUbIUZxzQaU1I4s_pgqsCK4KLM0gXG4Y926rR6Ntd4A8MZZhUi-EQS9-lNk6381J3kAgd9Y2hMDGNvMHu3G4kjYfsWq-KboZmJG8k4DnEPwxOC-6hgcXUXXxQTkymrlLqY7cty9nN4QICLXFij3KFDJqft87XCPwJ4yPKpfTJEdO5LVmUQ11C0lfpPoND3_F2yd3yXmyIJfUj-_1gSjvvL2VMLUOzwAU8XcSqrMIpFs2YjNkxtnYok0yBS5ZyPdwQ">>
                  }).

-define(EC_JWK, #{ kty => <<"EC">>, crv => <<"P-256">>,
                   x => <<"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU">>,
                   y => <<"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a1">>,
                   d => <<"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI">>
                 }).

-define(JWS, #{keys => [?RSA_JWK, ?OCT_JWK, ?EC_JWK]}).



rs256_verification_test() ->
    IdToken =
    <<"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE0NjA2MzE4MjEsImlzcyI6Imh0dHBzOi8vcHJvdG9uLnNjYy5raXQuZWR1Iiwic3ViIjoiam9lIiwiYXVkIjoiMTIzIiwiaWF0IjoxNDYwNjMxNTIxLCJhdXRoX3RpbWUiOjE0NjA2MzE1MjF9.nUKMCw_ppksTD49qWR7hs_FTNnVu2qaohnh67jANI9Cje7gaFi2puIsXbC_i0HoFnppR5mA_3B20f7X8O3UF3ZrgYyfjjAq5U3HeZ-Tx6xEd2EcJ-gfpVnoAJPa46Lx77NmApUyTAazXj8kjzgkh58_QDxujG13g55ckRG9qJfK3bX_h0ec07ARJWQSg_Zh8Q3lFB_iIbSDXOYegSAHhIpTxmuTA-qmPn3ySGIRirQt_-niek0-wyy5PAsxSU9lc42QIG7qdMLhvXsq5j52kPO9DA3vJNpGTloJ8H1AoE-ES8HpXH3RhRMe3cdiVyK2vTsPbRc0-GxkRZMKaocyOPQ">>,
    expired = erljwt:check_sig(IdToken, [rs256], ?JWS),
    ok.

compute_keys_test() ->
    D = <<"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI">>,
    X =  <<"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU">>,
    Y =  <<"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a1">>,
    PrivKeyIn = base64url:decode(D),
    {PubKey, PrivKey} = crypto:generate_key(ecdh, secp256r1, PrivKeyIn),
    io:format("privkey in:  ~p~nprivkey out: ~p~n", [PrivKeyIn, PrivKey]),
    io:format("encoded:~n~p~n~n~p~n~n", [base64url:encode(PrivKeyIn), base64url:encode(PrivKey)]),
    PubX = base64url:decode(X),
    PubY = base64url:decode(Y),
    PubIn = << 4:8, PubX/binary, PubY/binary >>,
    %% where does the 4 above come from?
    io:format("pubkey:~n~p~n~n~p~n~p~n~p~n",[PubKey, PubX, PubY, PubIn]),
    ?assertEqual(PubIn, PubKey),
    ok.



%% raw_sign_test() ->
%%     D = <<"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI">>,
%%     Payload = <<"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ">>,
%%     SignatureIn = <<"DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q">>,
%%     Key = base64url:decode(D),
%%     Signature = crypto:sign(ecdsa, sha256, Payload, [Key, secp256r1]),
%%     SigIn = base64url:decode(SignatureIn),
%%     %% ?assertEqual(byte_size(SigIn), byte_size(Signature)),
%%     ?assertEqual(SigIn, Signature).


crypto_roundtrip_test() ->
    D = <<"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI">>,
    PrivKeyIn = base64url:decode(D),
    Payload = <<"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ">>,
    {Pub, Priv} = crypto:generate_key(ecdh, secp256r1, PrivKeyIn),
    Signature = crypto:sign(ecdsa, sha256, Payload, [Priv, secp256r1] ),
    ?assertEqual(true, crypto:verify(ecdsa, sha256, Payload, Signature, [Pub, secp256r1])).


%% ec256_verification_test() ->
%%     JWT = <<"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q">>,
%%     io:format("~p~n", [erljwt:to_map(JWT)]),
%%     expired = erljwt:validate(JWT, erljwt:algorithms(), #{},  ?JWS),
%%     ok.

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

%% ec256_roundtrip_test() ->
%%     application:set_env(erljwt, add_iat, false),
%%     Claims = claims(),
%%     JWT = erljwt:create(es256, Claims, 10, ?EC_JWK),
%%     io:format("created jwt: ~p~n", [erljwt:to_map(JWT)]),
%%     Result = erljwt:validate(JWT, erljwt:algorithms(), #{}, ?JWS),
%%     true = valid_claims(Claims, Result).

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
    %% Result = erljwt:check_sig(JWT, [rs256], ?JWS),
    Result = erljwt:validate(JWT, [rs256], Claims, ?JWS),
    true = valid_claims(Claims, Result).

algo_fail_test() ->
    application:set_env(erljwt, add_iat, false),
    Claims = claims(),
    JWT = erljwt:create(hs256,Claims, 10, ?OCT_JWK),
    algo_not_allowed = erljwt:check_sig(JWT, [rs256], ?JWS).

garbage_test() ->
    %% JWT = erljwt:create(rs256, claims(), 10, ?RSA_JWK),
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
