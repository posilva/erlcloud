-module('erlcloud_ssm_tests').
-include_lib("eunit/include/eunit.hrl").

-export([start/0]).
-export([stop/1]).

-define(_ssm_test(T), {?LINE, T}).
-define(_f(F), fun() -> F end).

start() ->
    meck:new(erlcloud_httpc),
    ok.

stop(_) ->
    meck:unload(erlcloud_httpc).
