%%
%% JWT Library for Erlang.
%% by Bas Wegh at KIT (http://kit.edu)
%%

-module(erljwt).

-include_lib("public_key/include/public_key.hrl").

-export([check_sig/3]).
-export([validate/4]).
-export([to_map/1]).
-export([create/3, create/4]).
-export([algorithms/0]).

-define(ALL_ALGOS, [none, hs256, hs384, hs512, rs256, rs384, rs512]).
                    %% es256, es384, es512]).


algorithms() ->
    ?ALL_ALGOS.

check_sig(Jwt,AllowedAlgos, Key) ->
    validate(Jwt, AllowedAlgos, #{}, Key).

validate(Jwt, AllowedAlgos, ExpClaims, KeyList)
  when is_list(KeyList), is_list(AllowedAlgos), is_map(ExpClaims) ->
    validate_jwt(jwt_to_map(Jwt), AllowedAlgos, ExpClaims, KeyList);
validate(Jwt, AllowedAlgos, Claims, #{keys := KeyList}) ->
    validate(Jwt, AllowedAlgos, Claims, KeyList);
validate(Jwt, AllowedAlgos, Claims, #{kty := _} = Key) ->
    validate(Jwt, AllowedAlgos, Claims, [Key]).

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

jwt_to_map(Jwt) ->
    decode_jwt(split_jwt_token(Jwt)).

validate_jwt(#{ header := Header, claims := Claims} = Jwt, Algos, ExpClaims,
             KeyList) ->
    Algo = algo_to_atom(maps:get(alg, Header, undefined)),
    ValidAlgo = lists:member(Algo, Algos),
    KeyId = maps:get(kid, Header, undefined),
    ValidSignature = validate_signature(ValidAlgo, Algo, KeyId, Jwt, KeyList),
    ExpiresAt  = maps:get(exp, Claims, undefined),
    NotBefore  = maps:get(nbf, Claims, undefined),
    IssuedAt  = maps:get(iat, Claims, undefined),
    StillValid = still_valid(ExpiresAt),
    AlreadyValid = already_valid(NotBefore),
    IssuedInPast = already_valid(IssuedAt),
    InvalidClaims = validate_claims(Claims, maps:to_list(ExpClaims), []),
    return_validation_result(ValidSignature, StillValid, AlreadyValid,
                             IssuedInPast, InvalidClaims, Jwt);
validate_jwt(_, _, _, _) ->
    invalid.

validate_signature(true, Algorithm, KeyId, #{signature := Signature,
                                             payload := Payload}, KeyList)
  when is_atom(Algorithm) ->
    Key = erljwt_key:get_needed(Algorithm, KeyId, KeyList),
    erljwt_sig:verify(Signature, Algorithm, Payload, Key);
validate_signature(false, _, _, _, _) ->
    algo_not_allowed;
validate_signature(_, _, _, _, _) ->
    false.

validate_claims(_, [], InvalidClaims) ->
    InvalidClaims;
validate_claims(Claims, [{Key, Value} | Tail], InvalidClaims) ->
    AKey = erljwt_util:try_to_atom(Key),
    ClaimValue = maps:get(AKey, Claims, undefined),
    NewInvalidClaims = validate_claim(AKey, Value, ClaimValue, InvalidClaims),
    validate_claims(Claims, Tail, NewInvalidClaims).

validate_claim(_Key, Value, Value, InvalidClaims) ->
    InvalidClaims;
validate_claim(aud, ListOfAud, Aud, InvalidClaims) when is_list(ListOfAud) ->
    Member = lists:is_member(Aud, ListOfAud),
    add_key_if_false(Member, aud, InvalidClaims);
validate_claim(Key, _, _, InvalidClaims) ->
    [ Key | InvalidClaims].

add_key_if_false(false, Key, InvalidClaims) ->
    [Key | InvalidClaims];
add_key_if_false(_, _Key, InvalidClaims) ->
    InvalidClaims.


return_validation_result(true, true, true, true, [], Jwt) ->
    maps:with([header, claims, signature], Jwt);
return_validation_result(false, _, _, _, _, _) ->
    invalid;
return_validation_result(true, false, _, _, _, _) ->
    expired;
return_validation_result(true, _, false, _, _, _) ->
    not_yet_valid;
return_validation_result(true, _, _, false, _, _) ->
    not_issued_in_past;
return_validation_result(true, _, _, _, InvalidClaims, _)
  when InvalidClaims /= [] ->
    {invalid_claims, InvalidClaims};
return_validation_result(Error, _, _, _, [], _) ->
    Error.


%% jwt_check_signature(EncSignature, Algo, Payload,
%%                     #{kty := <<"RSA">>, n := N, e:= E})
%%   when Algo == rs256; Algo == rs384; Algo == rs512->
%%     Signature = erljwt_util:safe_base64_decode(EncSignature),
%%     Hash = algo_to_hash(Algo),
%%     crypto:verify(rsa, Hash, Payload, Signature,
%%                   [erljwt_util:base64_to_unsiged(E),
%%                    erljwt_util:base64_to_unsiged(N)]);
%% jwt_check_signature(EncSignature, Algo, Payload,
%%                     #{kty := <<"EC">>, x := X0, y := Y0})
%%   when Algo == es256; Algo == es384; Algo == es512->
%%     Signature = erljwt_util:safe_base64_decode(EncSignature),
%%     X = erljwt_util:safe_base64_decode(X0),
%%     Y = erljwt_util:safe_base64_decode(Y0),
%%     Key = <<4:8, X/binary, Y/binary >>,
%%     Curve = algo_to_curve(Algo),
%%     {R, S} = ec_get_r_s(Signature, Algo),
%%     SigValue = #'ECDSA-Sig-Value'{r = binary:decode_unsigned(R),
%%                                   s = binary:decode_unsigned(S)},
%%     Asn1Sig = public_key:der_encode('ECDSA-Sig-Value', SigValue),
%%     crypto:verify(ecdsa, algo_to_hash(Algo), Payload, Asn1Sig, [Key, Curve]);
%% jwt_check_signature(Signature, Algo, Payload, SharedKey)
%%   when Algo == hs256; Algo == hs384; Algo == hs512 ->
%%     Signature =:= jwt_sign(Algo, Payload, SharedKey);
%% jwt_check_signature(Signature, none, _Payload, _Key) ->
%%     Signature =:= <<"">>;
%% jwt_check_signature(_Signature, _Algo, _Payload, Error) when is_atom(Error) ->
%%     Error;
%% jwt_check_signature(_Signature, _Algo, _Payload, _Key) ->
%%     invalid.




still_valid(undefined) ->
    true;
still_valid(ExpiresAt) when is_number(ExpiresAt) ->
    SecondsLeft = ExpiresAt - erljwt_util:epoch(),
    SecondsLeft > 0;
still_valid(_) ->
    false.

already_valid(undefined) ->
    true;
already_valid(NotBefore) when is_number(NotBefore) ->
    SecondsPassed = erljwt_util:epoch() - NotBefore,
    SecondsPassed >= 0;
already_valid(_) ->
    false.


split_jwt_token(Token) ->
    binary:split(Token, [<<".">>], [global]).

decode_jwt([Header, ClaimSet, Signature]) ->
    HeaderMap = erljwt_util:base64_to_map(Header),
    ClaimSetMap = erljwt_util:base64_to_map(ClaimSet),
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




jwt_add_claims(false, undefined, ClaimsMap) ->
    ClaimsMap;
jwt_add_claims(true, ExpSeconds, ClaimsMap) ->
    Now = erljwt_util:epoch(),
    NewClaims = maps:put(iat, Now, ClaimsMap),
    jwt_add_claims(false, ExpSeconds, NewClaims);
jwt_add_claims(AddIat, ExpSeconds, ClaimsMap)  ->
    Expiration = erljwt_util:epoch() + ExpSeconds,
    NewClaims = maps:put(exp, Expiration, ClaimsMap),
    jwt_add_claims(AddIat, undefined, NewClaims).


return_signed_jwt(Alg, Payload, Key) ->
    handle_signature(erljwt_sig:create(Alg, Payload, Key), Payload).

handle_signature(Signature, Payload) when is_binary(Signature) ->
    <<Payload/binary, ".", Signature/binary>>;
handle_signature(Error, _) when is_atom(Error) ->
    Error.


jwt_header(Algo) ->
    create_header(algo_to_binary(Algo)).
create_header(Algo) when is_binary(Algo) ->
    #{ alg => Algo, typ => <<"JWT">>};
create_header(_) ->
    #{ typ => <<"JWT">>}.

-define(ALGO_MAPPING, [
                       { none, <<"none">> , none, undefined},
                       { rs256, <<"RS256">>, sha256, undefined },
                       { rs384, <<"RS384">>, sha384, undefined },
                       { rs512, <<"RS512">>, sha512, undefined },
                       { es256, <<"ES256">>, sha256, secp256r1 },
                       { es384, <<"ES384">>, sha384, secp384r1 },
                       { es512, <<"ES512">>, sha512, secp521r1 },
                       { hs256, <<"HS256">>, sha256, undefined },
                       { hs384, <<"HS384">>, sha384, undefined },
                       { hs512, <<"HS512">>, sha512, undefined }
                      ]).

algo_to_atom(Name) ->
    handle_find_result(lists:keyfind(Name, 2, ?ALGO_MAPPING), 1).

algo_to_binary(Atom) ->
    handle_find_result(lists:keyfind(Atom, 1, ?ALGO_MAPPING), 2).

handle_find_result(false, _) ->
    unknown;
handle_find_result(Term, Index) ->
    element(Index, Term).
