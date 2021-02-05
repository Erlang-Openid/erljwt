-module(erljwt_sig).
-include_lib("public_key/include/public_key.hrl").


-export([verify/4, create/3,
         algo_to_atom/1,
         algo_to_binary/1]).

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

verify(EncSignature, Algo, Payload,
                    #{kty := <<"RSA">>, n := N, e:= E})
  when Algo == rs256; Algo == rs384; Algo == rs512->
    Signature = erljwt_util:safe_base64_decode(EncSignature),
    Hash = algo_to_hash(Algo),
    crypto:verify(rsa, Hash, Payload, Signature,
                  [erljwt_util:base64_to_unsiged(E),
                   erljwt_util:base64_to_unsiged(N)]);
verify(EncSignature, Algo, Payload,
                    #{kty := <<"EC">>, x := X0, y := Y0})
  when Algo == es256; Algo == es384; Algo == es512->
    Signature = erljwt_util:safe_base64_decode(EncSignature),
    X = erljwt_util:safe_base64_decode(X0),
    Y = erljwt_util:safe_base64_decode(Y0),
    Key = <<4:8, X/binary, Y/binary >>,
    Curve = algo_to_curve(Algo),
    {R, S} = ec_get_r_s(Signature, Algo),
    SigValue = #'ECDSA-Sig-Value'{r = binary:decode_unsigned(R),
                                  s = binary:decode_unsigned(S)},
    Asn1Sig = public_key:der_encode('ECDSA-Sig-Value', SigValue),
    crypto:verify(ecdsa, algo_to_hash(Algo), Payload, Asn1Sig, [Key, Curve]);
verify(Signature, Algo, Payload, SharedKey)
  when Algo == hs256; Algo == hs384; Algo == hs512 ->
    Signature =:= create(Algo, Payload, SharedKey);
verify(Signature, none, _Payload, _Key) ->
    Signature =:= <<"">>;
verify(_Signature, _Algo, _Payload, Error) when is_atom(Error) ->
    Error;
verify(_Signature, _Algo, _Payload, _Key) ->
    invalid.


-ifdef(OTP_RELEASE).
-if(OTP_RELEASE >= 23).
hmac(Algo, Key, Payload) ->
    crypto:mac(hmac, algo_to_hash(Algo), convert_key(Key), Payload).
-else.
hmac(Algo, Key, Payload) ->
    crypto:hmac(algo_to_hash(Algo), convert_key(Key), Payload).
-endif.
-else.
hmac(Algo, Key, Payload) ->
    crypto:hmac(algo_to_hash(Algo), convert_key(Key), Payload).
-endif.


create(Algo, Payload, Key)
  when Algo == rs256; Algo == rs384; Algo == rs512 ->
    base64url:encode(crypto:sign(rsa, algo_to_hash(Algo), Payload,
                                 convert_key(Key)));
create(Algo, Payload, Key)
  when Algo == es256; Algo == es384; Algo == es512 ->
    Asn1Sig = crypto:sign(ecdsa, algo_to_hash(Algo), Payload,
                          [convert_key(Key), algo_to_curve(Algo)]),
    #'ECDSA-Sig-Value'{r = R, s = S} = public_key:der_decode('ECDSA-Sig-Value',
                                                             Asn1Sig),
    base64url:encode(ec_signature(R, S, Algo));
create(Algo, Payload, Key)
  when Algo == hs256; Algo == hs384; Algo == hs512 ->
    base64url:encode(hmac(Algo, Payload, Key));
create(none, _Payload, _Key) ->
    <<"">>;
create(_, _, _) ->
    alg_not_supported.

ec_get_r_s(<<R:32/binary, S:32/binary>>, es256) ->
    {R, S};
ec_get_r_s(<<R:48/binary, S:48/binary>>, es384) ->
    {R, S};
ec_get_r_s(<<R:66/binary, S:66/binary>>, es512) ->
    {R, S}.

ec_signature(R, S, es256) ->
    <<R:256, S:256>>;
ec_signature(R, S, es384) ->
    <<R:384, S:384>>;
ec_signature(R, S, es512) ->
    <<0:7, R:521, 0:7, S:521>>.

algo_to_hash(Atom) ->
    handle_find_result(lists:keyfind(Atom, 1, ?ALGO_MAPPING), 3).

algo_to_curve(Atom) ->
    handle_find_result(lists:keyfind(Atom, 1, ?ALGO_MAPPING), 4).

handle_find_result(false, _) ->
    unknown;
handle_find_result(Term, Index) ->
    element(Index, Term).

convert_key(#{kty := <<"oct">>, k := Key}) ->
    Key;
convert_key(#{kty := <<"RSA">>,
              n := N, e := E, d := D }) ->
    [erljwt_util:base64_to_unsiged(E), erljwt_util:base64_to_unsiged(N),
     erljwt_util:base64_to_unsiged(D)];
convert_key(#{kty := <<"EC">>, d := D}) ->
    erljwt_util:base64_to_unsiged(D).
