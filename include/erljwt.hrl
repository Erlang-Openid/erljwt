
-type algorithm() :: none | hs256 | hs384 | hs512 | rs256 | rs384 | rs512 |
                     es256 | es384 | es512.
-type algo_list() :: [algorithm()].

-type jwt() :: binary().

-type key_type() :: <<_:24>> | <<_:16>>.
-type oct_key() :: #{kty => key_type(), k => binary(), kid => binary() }.
-type rsa_key() :: #{kty => key_type(), e => binary(), n => binary(),
                     d => binary(), kid => binary() }.
-type ec_key() :: #{kty => key_type(), x => binary(), y => binary(),
                    d => binary(), kid => binary() }.
-type key() :: oct_key() | rsa_key() .
-type keyid() :: binary().
-type keys() :: #{keys => [key()]} | key() | [key()].
-type header() :: map().
-type claims() :: map().
-type exp_seconds() :: integer() | undefined.
-type exp_claims() :: claims().
-type error_res() :: {error, atom()} |
                     {error, {invalid_claims, [ atom() | binary() ]}}.
-type jwt_result() :: {ok, #{ header => _, claims => _, signatrue => _}}
                | error_res().
-type key_result() :: {ok, key()} | error_res().

% Allowed clock difference in seconds between server and client when checking
% the nbf (not yet valid) check.
-define(JWT_ALLOWED_CLOCK_SKEW, 300).
