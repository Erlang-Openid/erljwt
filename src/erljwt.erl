%%
%% JWT Library for Erlang.
%% by Bas Wegh at KIT (http://kit.edu)
%%

-module(erljwt).

-include_lib("public_key/include/public_key.hrl").

-export([parse/2]).
-export([to_map/1]).
-export([create/3, create/4]).

parse(Jwt, KeyList) when is_list(KeyList) ->
    validate_jwt(jwt_to_map(Jwt), KeyList);
parse(Jwt, #{keys := KeyList}) ->
    parse(Jwt, KeyList);
parse(Jwt, Key) ->
    parse(Jwt, [to_jwk(Key)]).

to_map(Jwt) ->
    maps:with([header, claims, signature], jwt_to_map(Jwt)).

create(Alg, ClaimSetMap, Key) when is_map(ClaimSetMap) ->
    create(Alg, ClaimSetMap, undefined, Key).

create(Alg, ClaimSetMap, ExpirationSeconds, Key) when is_map(ClaimSetMap) ->
    NeedsIat = not maps:is_key(iat, ClaimSetMap),
    AddIat = application:get_env(erljwt, add_iat, true) and NeedsIat,
    ClaimSetExpMap = jwt_add_claims(AddIat, ExpirationSeconds, ClaimSetMap),
    ClaimSet = base64url:encode(jsone:encode(ClaimSetExpMap)),
    Header = base64url:encode(jsone:encode(jwt_header(Alg))),
    Payload = <<Header/binary, ".", ClaimSet/binary>>,
    return_signed_jwt(Alg, Payload, Key).


%% ========================================================================
%%                       INTERNAL
%% ========================================================================

to_jwk(#'RSAPublicKey'{ modulus = N, publicExponent = E}) ->
    Encode = fun(Int) ->
                     base64url:encode(binary:encode_unsigned(Int))
             end,
    #{kty => <<"RSA">>, e => Encode(E), n => Encode(N) };
to_jwk(Key) ->
    Key.

jwt_to_map(Jwt) ->
    decode_jwt(split_jwt_token(Jwt)).

validate_jwt(#{ header := Header, claims := Claims} = Jwt, KeyList) ->
    Algorithm = maps:get(alg, Header, undefined),
    KeyId = maps:get(kid, Header, undefined),
    ValidSignature = validate_signature(Algorithm, KeyId, Jwt, KeyList),
    ExpiresAt  = maps:get(exp, Claims, undefined),
    NotBefore  = maps:get(nbf, Claims, undefined),
    IssuedAt  = maps:get(iat, Claims, undefined),
    StillValid = still_valid(ExpiresAt),
    AlreadyValid = already_valid(NotBefore),
    IssuedInPast = already_valid(IssuedAt),
    return_validation_result(ValidSignature, StillValid, AlreadyValid,
                             IssuedInPast, Jwt);
validate_jwt(_, _) ->
    invalid.

validate_signature(Algorithm, KeyId, #{signature := Signature,
                                       payload := Payload}, KeyList)
  when is_binary(Algorithm) ->
    Key = get_needed_key(Algorithm, KeyId, KeyList),
    jwt_check_signature(Signature, Algorithm, Payload, Key);
validate_signature(_, _, _, _) ->
    false.

return_validation_result(true, true, true, true, Jwt) ->
    maps:with([header, claims, signature], Jwt);
return_validation_result(false, _, _, _, _) ->
    invalid;
return_validation_result(_, false, _, _, _) ->
    expired;
return_validation_result(_, _, false, _, _) ->
    not_yet_valid;
return_validation_result(_, _, _, false, _) ->
    not_issued_in_past;
return_validation_result(Error, _, _, _, _) ->
    Error.



get_needed_key(<<"none">>, _, _) ->
    <<>>;
get_needed_key(<<"HS256">>, _KeyId, [ Key ]) ->
    Key;
get_needed_key(<<"HS256">>, _KeyId, _) ->
    too_many_keys;
get_needed_key(<<"RS256">>, KeyId, KeyList) ->
    filter_rsa_key(KeyId, KeyList, []);
get_needed_key(_, _, _) ->
    unknown_algorithm.

jwt_check_signature(EncSignature, <<"RS256">>, Payload,
                    #{kty := <<"RSA">>, n := N, e:= E}) ->
    Signature = safe_base64_decode(EncSignature),
    Decode = fun(Base64) ->
                     binary:decode_unsigned(safe_base64_decode(Base64))
             end,
    crypto:verify(rsa, sha256, Payload, Signature, [Decode(E), Decode(N)]);
jwt_check_signature(Signature, <<"HS256">>, Payload, SharedKey)
  when is_list(SharedKey); is_binary(SharedKey)->
    Signature =:= jwt_sign(hs256, Payload, SharedKey);
jwt_check_signature(Signature, <<"none">>, _Payload, _Key) ->
    Signature =:= <<"">>;
jwt_check_signature(_Signature, _Algo, _Payload, Error) when is_atom(Error) ->
    Error;
jwt_check_signature(_Signature, _Algo, _Payload, _Key) ->
    invalid.

filter_rsa_key(_, [], []) ->
    no_key_found;
filter_rsa_key(_, [], [Key]) ->
    Key;
filter_rsa_key(_, [], _) ->
    too_many_keys;
filter_rsa_key(KeyId, [ #{kty := <<"RSA">>, kid:= KeyId } = Key | _], _) ->
    Key;
filter_rsa_key(KeyId, [ #{kty := <<"RSA">>, kid := _Other} | Tail], List ) ->
    filter_rsa_key(KeyId, Tail, List);
filter_rsa_key(KeyId, [ #{kty := <<"RSA">>, use:=<<"sig">>} = Key | Tail],
               List ) ->
    filter_rsa_key(KeyId, Tail, [ Key | List ] );
filter_rsa_key(KeyId, [ #{kty := <<"RSA">>, use:= _} | Tail], List ) ->
    filter_rsa_key(KeyId, Tail, List);
filter_rsa_key(KeyId, [ #{kty := <<"RSA">>} = Key | Tail], List ) ->
    filter_rsa_key(KeyId, Tail, [ Key | List ] );
filter_rsa_key(KeyId, [ _ | Tail ], List) ->
    filter_rsa_key(KeyId, Tail, List).


still_valid(undefined) ->
    true;
still_valid(ExpiresAt) when is_number(ExpiresAt) ->
    SecondsLeft = ExpiresAt - epoch(),
    SecondsLeft > 0;
still_valid(_) ->
    false.

already_valid(undefined) ->
    true;
already_valid(NotBefore) when is_number(NotBefore) ->
    SecondsPassed = epoch() - NotBefore,
    io:format("seconds passed: ~p~n", [SecondsPassed]),
    SecondsPassed >= 0;
already_valid(_) ->
    false.


split_jwt_token(Token) ->
    binary:split(Token, [<<".">>], [global]).

decode_jwt([Header, ClaimSet, Signature]) ->
    HeaderMap = base64_to_map(Header),
    ClaimSetMap = base64_to_map(ClaimSet),
    Payload = <<Header/binary, ".", ClaimSet/binary>>,
    create_jwt_map(HeaderMap, ClaimSetMap, Signature, Payload);
decode_jwt(_) ->
    invalid.

create_jwt_map(HeaderMap, ClaimSetMap, Signature, Payload)
  when is_map(HeaderMap), is_map(ClaimSetMap), is_binary(Payload) ->
    #{
       header => HeaderMap,
       claims => ClaimSetMap,
       signature => Signature,
       payload => Payload
     };
create_jwt_map(_, _, _, _) ->
    invalid.


base64_to_map(Base64) ->
    Bin = safe_base64_decode(Base64),
    handle_json_result(safe_jsone_decode(Bin)).

handle_json_result(PropList) when is_list(PropList) ->
    %% force absence of duplicate keys
    Keys = [K || {K, _} <- PropList],
    SameLength = (length(lists:usort(Keys)) =:= length(Keys)),
    return_decoded_jwt_or_error(SameLength, PropList);
handle_json_result(_) ->
    invalid.

return_decoded_jwt_or_error(true, PropList) ->
    maps:from_list(PropList);
return_decoded_jwt_or_error(_, _) ->
    invalid.


jwt_add_claims(false, undefined, ClaimsMap) ->
    ClaimsMap;
jwt_add_claims(true, ExpSeconds, ClaimsMap) ->
    Now = epoch(),
    NewClaims = maps:put(iat, Now, ClaimsMap),
    jwt_add_claims(false, ExpSeconds, NewClaims);
jwt_add_claims(AddIat, ExpSeconds, ClaimsMap)  ->
    Expiration = epoch() + ExpSeconds,
    NewClaims = maps:put(exp, Expiration, ClaimsMap),
    jwt_add_claims(AddIat, undefined, NewClaims).


return_signed_jwt(Alg, Payload, Key) ->
    handle_signature(jwt_sign(Alg, Payload, Key), Payload).

handle_signature(Signature, Payload) when is_binary(Signature) ->
    <<Payload/binary, ".", Signature/binary>>;
handle_signature(Error, _) when is_atom(Error) ->
    Error.

jwt_sign(rs256, Payload, #'RSAPrivateKey'{} = Key) ->
    base64url:encode(public_key:sign(Payload, sha256, Key));
jwt_sign(hs256, Payload, Key) ->
    base64url:encode(crypto:hmac(sha256, Key, Payload));
jwt_sign(none, _Payload, _Key) ->
    <<"">>;
jwt_sign(_, _, _) ->
    alg_not_supported.

jwt_header(rs256) ->
    #{ alg => <<"RS256">>, typ => <<"JWT">>};
jwt_header(hs256) ->
    #{ alg => <<"HS256">>, typ => <<"JWT">>};
jwt_header(none) ->
    #{ alg => <<"none">>, typ => <<"JWT">>};
jwt_header(_) ->
    #{ typ => <<"JWT">>}.

safe_base64_decode(Base64) ->
    Fun = fun() ->
                  base64url:decode(Base64)
          end,
    result_or_invalid(Fun).


safe_jsone_decode(Bin) ->
    Fun = fun() ->
                  jsone:decode(Bin, [{keys, attempt_atom},
                                     {object_format, proplist}])
          end,
    result_or_invalid(Fun).

result_or_invalid(Fun) ->
    try
        Fun()
    of
        Result -> Result
    catch _:_ ->
            invalid
    end.

epoch() ->
    erlang:system_time(seconds).
