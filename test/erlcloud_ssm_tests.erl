-module('erlcloud_ssm_tests').
-include_lib("eunit/include/eunit.hrl").

-export([start/0]).
-export([stop/1]).

-define(_ssm_test(T), {?LINE, T}).
-define(_f(F), fun() -> F end).

-define(ACCESS_KEY_ID, string:copies("A", 20)).
-define(SECRET_ACCESS_KEY, string:copies("a", 40)).

-define(_service_config, erlcloud_ssm:configure(?ACCESS_KEY_ID, ?SECRET_ACCESS_KEY)).

%%==============================================================================
%% Test generator functions
%%==============================================================================

erlcloud_ssm_test_() ->
    {foreach, fun start/0, fun stop/1, [
    ]}.


%%==============================================================================
%% Setup functions
%%==============================================================================

start() ->
    meck:new(erlcloud_httpc),
    ok.

stop(_) ->
    meck:unload(erlcloud_httpc).

%%==============================================================================
%% Test functions
%%==============================================================================
ssm_input_tests(_) ->
    ok.

ssm_output_tests(_) ->
    ok.


%%==============================================================================
%% Internal functions
%%==============================================================================
input_tests(ResponseBody, Tests) ->
    [input_test(ResponseBody, Test) || Test <- Tests].

input_test(ResponseBody, {Line, {Description, Fun, ExpectedParams}}) ->
    {Description, {Line,
        fun() ->
            meck:expect(
                erlcloud_httpc,
                request,
                fun(_Url, post, _Headers, RequestBody, _Timeout, _Config) ->
                    ActualParams = jsx:decode(RequestBody),
                    ?assertEqual(sort_json(ExpectedParams), sort_json(ActualParams)),
                    {ok, {{200, "OK"}, [], ResponseBody}}
                end
            ),
            erlcloud_emr:configure(?ACCESS_KEY_ID, ?SECRET_ACCESS_KEY),
            Fun()
        end
    }}.

output_tests(Fun, Tests) ->
    [output_test(Fun, Test) || Test <- Tests].

output_test(Fun, {Line, {Description, ResponseBody, Expected}}) ->
    {Description, {Line,
        fun() ->
            meck:expect(
                erlcloud_httpc,
                request,
                fun(_Url, post, _Headers, _Body, _Timeout, _Config) ->
                    {ok, {{200, "OK"}, [], ResponseBody}}
                end
            ),
            ?_service_config,
            ?assertEqual(Expected, _Actual = Fun())
        end
    }}.

sort_json([{_, _} | _] = Json) ->
    Sorted = [{Key, sort_json(Value)} || {Key, Value} <- Json],
    lists:keysort(1, Sorted);
sort_json([_ | _] = Json) ->
    [sort_json(Item) || Item <- Json];
sort_json(Value) ->
    Value.
