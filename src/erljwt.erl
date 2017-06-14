%%
%% JWT Library for Erlang.
%% by Bas Wegh at KIT (http://kit.edu)
%%

-module(erljwt).

-include("erljwt.hrl").
-include_lib("public_key/include/public_key.hrl").

-export([check_sig/3]).
-export([validate/4]).
-export([to_map/1]).
-export([create/3, create/4, create/5]).
-export([algorithms/0]).

-define(ALL_ALGOS, [none, hs256, hs384, hs512, rs256, rs384, rs512,
                    es256, es384, es512]).

-spec algorithms() -> algo_list().
algorithms() ->
    ?ALL_ALGOS.

-spec check_sig(jwt(), algo_list(), keys()) -> jwt_result().
check_sig(Jwt, AllowedAlgos, Key) ->
    validate(Jwt, AllowedAlgos, #{}, Key).


-spec validate(jwt(), algo_list(), exp_claims(), keys()) -> jwt_result().
validate(Jwt, AllowedAlgos, ExpClaims, KeyList)
  when is_list(KeyList), is_list(AllowedAlgos), is_map(ExpClaims) ->
    validate_jwt(jwt_to_map(Jwt), AllowedAlgos, ExpClaims, KeyList);
validate(Jwt, AllowedAlgos, Claims, #{keys := KeyList}) ->
    validate(Jwt, AllowedAlgos, Claims, KeyList);
validate(Jwt, AllowedAlgos, Claims, #{kty := _} = Key) ->
    validate(Jwt, AllowedAlgos, Claims, [Key]).

-spec to_map(jwt()) -> jwt_result().
to_map(Jwt) ->
    {ok, maps:with([header, claims, signature], jwt_to_map(Jwt))}.

-spec create(algorithm(), claims(), key()) -> jwt().
create(Alg, ClaimSetMap, Key) when is_map(ClaimSetMap) ->
    create(Alg, ClaimSetMap, #{}, undefined, Key).

-spec create(algorithm(), claims(), exp_seconds(), key()) -> jwt().
create(Alg, ClaimSetMap, ExpirationSeconds, Key) ->
    create(Alg, ClaimSetMap, #{}, ExpirationSeconds, Key).

-spec create(algorithm(), claims(), header(), exp_seconds(), key()) -> jwt().
create(Alg, ClaimSetMap, HeaderMapIn, ExpirationSeconds, Key)
  when is_map(ClaimSetMap), is_map(HeaderMapIn) ->
    NeedsIat = not maps:is_key(iat, ClaimSetMap),
    AddIat = application:get_env(erljwt, add_iat, true) and NeedsIat,
    ClaimSetExpMap = jwt_add_claims(AddIat, ExpirationSeconds, ClaimSetMap),
    ClaimSet = base64url:encode(jsone:encode(ClaimSetExpMap)),
    HeaderMap = maps:merge(HeaderMapIn, jwt_header(Alg)),
    Header = base64url:encode(jsone:encode(HeaderMap)),
    Payload = <<Header/binary, ".", ClaimSet/binary>>,
    return_signed_jwt(Alg, Payload, Key).


%% ========================================================================
%%                       INTERNAL
%% ========================================================================

jwt_to_map(Jwt) ->
    decode_jwt(split_jwt_token(Jwt)).

validate_jwt(#{ header := Header, claims := Claims} = Jwt, Algos, ExpClaims,
             KeyList) ->
    Algo = erljwt_sig:algo_to_atom(maps:get(alg, Header, undefined)),
    ValidAlgo = lists:member(Algo, Algos),
    KeyId = maps:get(kid, Header, undefined),
    ValidSignature = validate_signature(ValidAlgo, Algo, KeyId, Jwt, KeyList),
    CriticalClaims = convert_to_atoms(maps:get(crit, Header, [])),
    EnforceChecks = [{exp, undefined}, {nbf, undefined}, {iat, undefined}],
    CheckClaims = maps:to_list(ExpClaims) ++ EnforceChecks,
    InvalidClaims = validate_claims(Claims, CheckClaims, CriticalClaims, []),
    return_validation_result(ValidSignature, InvalidClaims, Jwt);
validate_jwt(_, _, _, _) ->
    {error, no_jwt}.

validate_signature(true, Algorithm, KeyId, #{signature := Signature,
                                             payload := Payload}, KeyList)
  when is_atom(Algorithm) ->
    Key = erljwt_key:get_needed(Algorithm, KeyId, KeyList),
    verify_if_key(Key, Signature, Algorithm, Payload);
validate_signature(false, _, _, _, _) ->
    algo_not_allowed;
validate_signature(_, _, _, _, _) ->
    false.

verify_if_key({ok, Key}, Signature, Algorithm, Payload) ->
    erljwt_sig:verify(Signature, Algorithm, Payload, Key);
verify_if_key({error, Reason}, _Signature, _Algorithm, _Payload) ->
    Reason.




validate_claims(_, [], CriticalClaims, InvalidClaims) ->
    InvalidClaims ++ CriticalClaims;
validate_claims(Claims, [{Key, Value} | Tail], CritClaims, InvalidClaims) ->
    AKey = erljwt_util:try_to_atom(Key),
    ClaimValue = maps:get(AKey, Claims, undefined),
    IsCritial = lists:member(Key, CritClaims),
    NewInvalidClaims = validate_claim(AKey, Value, ClaimValue, IsCritial,
                                      InvalidClaims),
    NewCritClaims = lists:delete(Key, CritClaims),
    validate_claims(Claims, Tail, NewCritClaims, NewInvalidClaims).

validate_claim(aud, ListOfAud, Aud, _, InvalidClaims) when is_list(ListOfAud) ->
    Member = lists:member(Aud, ListOfAud),
    add_key_if_false(Member, aud, InvalidClaims);
validate_claim(exp, undefined, undefined, true, InvalidClaims) ->
    [exp | InvalidClaims ];
validate_claim(exp, undefined, Exp, _, InvalidClaims) ->
    add_key_if_false(still_valid(Exp), exp, InvalidClaims);
validate_claim(nbf, undefined, undefined, true, InvalidClaims) ->
    [nbf | InvalidClaims];
validate_claim(nbf, undefined, Nbf, _, InvalidClaims) ->
    add_key_if_false(already_valid(Nbf), nbf, InvalidClaims);
validate_claim(iat, undefined, undefined, true, InvalidClaims) ->
    [ iat | InvalidClaims ];
validate_claim(iat, undefined, Iat, _, InvalidClaims) ->
    add_key_if_false(already_valid(Iat), iat, InvalidClaims);
validate_claim(_Key, Value, Value, _, InvalidClaims) ->
    InvalidClaims;
validate_claim(Key, _, _, _, InvalidClaims) ->
    [ Key | InvalidClaims].

add_key_if_false(false, Key, InvalidClaims) ->
    [Key | InvalidClaims];
add_key_if_false(_, _Key, InvalidClaims) ->
    InvalidClaims.

return_validation_result(true, [], Jwt) ->
    {ok, maps:with([header, claims, signature], Jwt)};
return_validation_result(false, _, _) ->
    {error, invalid};
return_validation_result(true, List, _Jwt) ->
    Expired = lists:member(exp, List),
    NotYetValid = lists:member(nbf, List),
    IssuedInFuture = lists:member(iat, List),
    {error, validation_error(Expired, NotYetValid, IssuedInFuture, List)};
return_validation_result(Error, _, _) when is_atom(Error) ->
    {error, Error}.

validation_error(true, _, _, _) ->
    expired;
validation_error(false, true, _, _) ->
    not_yet_valid;
validation_error(false, false, true, _) ->
    not_issued_in_past;
validation_error(false, false, false, InvalidClaims)
  when InvalidClaims /= [] ->
    {invalid_claims, InvalidClaims}.


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

convert_to_atoms(ListIn) ->
    ToAtom = fun(B, List) ->
                     [ erljwt_util:try_to_atom(B) | List]
             end,
    lists:foldl(ToAtom, [], ListIn).


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
    create_header(erljwt_sig:algo_to_binary(Algo)).
create_header(Algo) when is_binary(Algo) ->
    #{ alg => Algo, typ => <<"JWT">>};
create_header(_) ->
    #{ typ => <<"JWT">>}.
