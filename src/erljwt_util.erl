-module(erljwt_util).
-export([
         try_to_atom/1,
         safe_base64_decode/1,
         safe_jsone_decode/1,
         base64_to_unsiged/1,
         base64_to_map/1,
         epoch/0
        ]).

try_to_atom(Bin) when is_binary(Bin) ->
    try
        binary_to_existing_atom(Bin, utf8)
    of
        Atom -> Atom
    catch _:_ ->
            Bin
    end;
try_to_atom(List) when is_list(List) ->
    try_to_atom(list_to_binary(List));
try_to_atom(Other) ->
    Other.


base64_to_map(Base64) ->
    Bin = safe_base64_decode(Base64),
    handle_json_result(safe_jsone_decode(Bin)).


safe_base64_decode(Base64) ->
    Fun = fun() ->
                  base64url:decode(Base64)
          end,
    result_or_invalid(Fun).

base64_to_unsiged(Base64) ->
    binary:decode_unsigned(safe_base64_decode(Base64)).


safe_jsone_decode(Bin) ->
    Fun = fun() ->
                  jsone:decode(Bin, [{keys, attempt_atom},
                                     {object_format, proplist}])
          end,
    result_or_invalid(Fun).

epoch() ->
    erlang:system_time(seconds).



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
result_or_invalid(Fun) ->
    try
        Fun()
    of
        Result -> Result
    catch _:_ ->
            invalid
    end.
