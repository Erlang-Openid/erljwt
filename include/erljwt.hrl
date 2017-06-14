
-type algorithm() :: none | hs256 | hs384 | hs512 | rs256 | rs384 | rs512 |
                     es256 | es384 | es512.
-type algo_list() :: [algorithm()].

-type jwt() :: binary().
-type key() :: #{kty := _}.
-type keyid() :: binary().
-type keys() :: #{keys := _} | key() | [key()].
-type header() :: map().
-type claims() :: map().
-type exp_seconds() :: integer() | undefined.
-type exp_claims() :: claims().
-type error_res() :: {error, atom()} |
                     {error, {invalid_claims, [ atom() | binary() ]}}.
-type jwt_result() :: {ok, #{ header := _, claims := _, signatrue := _}}
                | error_res().
-type key_result() :: {ok, key()} | error_res().
