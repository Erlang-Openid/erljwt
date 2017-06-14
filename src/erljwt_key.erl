-module(erljwt_key).

-include("erljwt.hrl").

-export([to_key_list/1, get_needed/3]).


-spec to_key_list(keys()) -> [key()].
to_key_list(Json) when is_binary(Json) ->
    to_key_list(erljwt_util:safe_jsone_decode(Json));
to_key_list(#{keys := KeyList}) when is_list(KeyList) ->
    KeyList;
to_key_list(#{kty := _} = Key) ->
    [Key];
to_key_list(invalid) ->
    [].



-spec get_needed(algorithm(), keyid(), [key()]) -> key_result().
get_needed(Algo, KeyId, KeyList)
  when Algo == hs256; Algo == hs384; Algo == hs512->
    filter_oct_key(KeyId, KeyList);
get_needed(Algo, KeyId, KeyList)
  when Algo == rs256; Algo == rs384; Algo == rs512 ->
    filter_rsa_key(KeyId, KeyList);
get_needed(Algo, KeyId, KeyList)
  when Algo == es256; Algo == es384; Algo == es512 ->
    filter_ec_key(KeyId, Algo, KeyList);
get_needed(none, _, _) ->
    {ok, <<>>};
get_needed(_, _, _) ->
    {error, unknown_algorithm}.


filter_oct_key(KeyId, KeyList) ->
    handle_filter_result(filter_key(KeyId, KeyList, [], <<"oct">>)).

filter_rsa_key(KeyId, KeyList) ->
    handle_filter_result(filter_key(KeyId, KeyList, [], <<"RSA">>)).

filter_ec_key(KeyId, Algo, KeyList) ->
    Keys = filter_key(KeyId, KeyList, [], <<"EC">>),
    handle_filter_result(filter_curve(Keys, [], Algo)).


handle_filter_result([]) ->
    {error, no_key_found};
handle_filter_result([Key]) ->
    {ok, Key};
handle_filter_result([_ | _ ]) ->
    {error, too_many_keys}.


filter_curve([], Keys, _) ->
    Keys;
filter_curve([#{crv := <<"P-256">>} = Key | Tail ], List, Algo)
  when Algo == es256->
    filter_curve(Tail, [Key | List], Algo);
filter_curve([#{crv := <<"P-384">>} = Key | Tail ], List, Algo)
  when Algo == es384->
    filter_curve(Tail, [Key | List], Algo);
filter_curve([#{crv := <<"P-521">>} = Key | Tail ], List, Algo)
  when Algo == es512->
    filter_curve(Tail, [Key | List], Algo);
filter_curve([_ | Tail ], List, Algo) ->
    filter_curve(Tail, List, Algo).


filter_key(_, [], Keys, _Type) ->
    Keys;
filter_key(KeyId, [ #{kty := Type, kid:= KeyId } = Key | _], _, Type) ->
    [Key];
filter_key(KeyId, [ #{kty := Type, kid := _Other} | Tail], List, Type) ->
    filter_key(KeyId, Tail, List, Type);
filter_key(KeyId, [ #{kty := Type, use:=<<"sig">>} = Key | Tail],
           List, Type) ->
    filter_key(KeyId, Tail, [ Key | List ], Type);
filter_key(KeyId, [ #{kty := Type, use:= _} | Tail], List, Type) ->
    filter_key(KeyId, Tail, List, Type);
filter_key(KeyId, [ #{kty := Type} = Key | Tail], List, Type) ->
    filter_key(KeyId, Tail, [ Key | List ], Type);
filter_key(KeyId, [ _ | Tail ], List, Type) ->
    filter_key(KeyId, Tail, List, Type).
