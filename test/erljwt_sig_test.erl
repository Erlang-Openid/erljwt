-module(erljwt_sig_test).

-include_lib("eunit/include/eunit.hrl").
-include_lib("public_key/include/public_key.hrl").

es512_verification_test() ->
    Signature = <<"AdwMgeerwtHoh-l192l60hp9wAHZFVJbLfD_UxMi70cwnZOYaRI1bKPWROc-mZZqwqT2SI-KGDKB34XO0aw_7XdtAG8GaSwFKdCAPZgoXD2YBJZCPEX3xKpRwcdOO8KpEHwJjyqOgzDO7iKvU8vcnwNrmxYbSW9ERBXukOXolLzeO_Jn">>,
    Payload = <<"eyJhbGciOiJFUzUxMiJ9.UGF5bG9hZA">>,
    X = <<"AekpBQ8ST8a8VcfVOTNl353vSrDCLLJXmPk06wTjxrrjcBpXp5EOnYG_NjFZ6OvLFV1jSfS9tsz4qUxcWceqwQGk">>,
    Y = <<"ADSmRA43Z1DSNx_RvcLI87cdL07l6jQyyBXMoxVg_l2Th-x3S1WDhjDly79ajL4Kkd0AZMaZmh9ubmf63e3kyMj2">>,
    Key = #{kty => <<"EC">>, x => X, y => Y},
    io:format("signature length: ~p~n",[byte_size(base64url:decode(Signature))]),
    true = erljwt_sig:verify(Signature, es512, Payload, Key).
