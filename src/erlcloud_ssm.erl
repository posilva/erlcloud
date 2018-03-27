%% @author Pedro Silva <posilva@gmail.com>
%% @doc
%%
%% Implementation of the AWS Systems Manager 
%% 
%% TODO
%% - Implement parameters store related methods to be used to 
%%   fetch configurations 
%% Docs: - http://boto3.readthedocs.io/en/latest/reference/services/ssm.html
%%       - https://docs.aws.amazon.com/systems-manager/latest/APIReference/
%% application:ensure_all_started(erlcloud). {ok, Conf} = erlcloud_aws:profile(). erlcloud_ssm:describe_parameters(Conf).
%% rr("include/erlcloud_aws.hrl").
%% {ok, Conf} = erlcloud_aws:profile().
%% erlcloud_ssm:describe_parameters(Conf).
%% @end
-module(erlcloud_ssm).

-include("erlcloud.hrl").
-include("erlcloud_aws.hrl").

%%%-------------------------------------------------------------------
%%% Types definitioins 
%%%-------------------------------------------------------------------
-type(parameters_list() :: [proplist:proplist()]).

-type(next_token_out() :: undefined | binary()).
-type(next_token_in() :: undefined | string()).

-type(parameter_filter_key() :: name | type | key_id).
-type(parameter_filter_ret() :: [{binary(), binary()} | {binary(), [binary()]}]).
%%%-------------------------------------------------------------------
%%% Export API functions
%%%-------------------------------------------------------------------
% Configuration setup helper functions 
-export([configure/2, configure/3, configure/4, configure/5,
         new/2, new/3, new/4, new/5]).

% Parameters Store - helpers
-export([parameter_filter/2]).

% Parameters Store
-export([
    describe_parameters/1, 
    describe_parameters/2, 
    describe_parameters/3,
    describe_parameters/4,
    describe_parameters/5
]). 

%%%-------------------------------------------------------------------
%%% API functions
%%%-------------------------------------------------------------------
%%% Handle configuration
-spec new(string(), string()) -> aws_config().
new(AccessKeyID, SecretAccessKey) ->
    #aws_config{access_key_id     = AccessKeyID,
                secret_access_key = SecretAccessKey,
                retry             = fun erlcloud_retry:default_retry/1}.

-spec new(string(), string(), string()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Host) ->
    #aws_config{access_key_id     = AccessKeyID,
                secret_access_key = SecretAccessKey,
                ssm_host          = Host,
                retry             = fun erlcloud_retry:default_retry/1}.

-spec new(string(), string(), string(), non_neg_integer()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Host, Port) ->
    #aws_config{access_key_id     = AccessKeyID,
                secret_access_key = SecretAccessKey,
                ssm_host          = Host,
                ssm_port          = Port,
                retry             = fun erlcloud_retry:default_retry/1}.

-spec new(string(), string(), string(), non_neg_integer(), string()) ->
    aws_config().
new(AccessKeyID, SecretAccessKey, Host, Port, Scheme) ->
    #aws_config{access_key_id     = AccessKeyID,
                secret_access_key = SecretAccessKey,
                ssm_host          = Host,
                ssm_port          = Port,
                ssm_scheme        = Scheme,
                retry             = fun erlcloud_retry:default_retry/1}.

-spec configure(string(), string()) -> ok.
configure(AccessKeyID, SecretAccessKey) ->
    put(aws_config, new(AccessKeyID, SecretAccessKey)),
    ok.

-spec configure(string(), string(), string()) -> ok.
configure(AccessKeyID, SecretAccessKey, Host) ->
    put(aws_config, new(AccessKeyID, SecretAccessKey, Host)),
    ok.

-spec configure(string(), string(), string(), non_neg_integer()) -> ok.
configure(AccessKeyID, SecretAccessKey, Host, Port) ->
    put(aws_config, new(AccessKeyID, SecretAccessKey, Host, Port)),
    ok.

-spec configure(string(), string(), string(), non_neg_integer(), string()) -> ok.
configure(AccessKeyID, SecretAccessKey, Host, Port, Scheme) ->
    put(aws_config, new(AccessKeyID, SecretAccessKey, Host, Port, Scheme)),
    ok.

%%% Parameters store API
-spec describe_parameters(AwsConfig :: aws_config())  -> {ok, any()} | {error, term()}.
describe_parameters(AwsConfig) -> 
    describe_parameters("", AwsConfig).

-spec describe_parameters(NextToken :: string(), 
                          AwsConfig :: aws_config())  -> {ok, any()} | {error, term()}.
describe_parameters(NextToken, AwsConfig) ->     
    describe_parameters(50, NextToken, AwsConfig).

-spec describe_parameters(MaxResults :: 1..50, 
                          NextToken :: string(), 
                          AwsConfig :: aws_config())  -> {ok, any()} | {error, term()}.
describe_parameters(MaxResults, NextToken, AwsConfig) -> 
    describe_parameters([], MaxResults, NextToken, AwsConfig).
    
-spec describe_parameters(ParameterFilters :: [],
                          MaxResults :: 1..50, 
                          NextToken :: string(), 
                          AwsConfig :: aws_config())  -> {ok, any()} | {error, term()}.
describe_parameters(ParameterFilters, MaxResults, NextToken, AwsConfig) -> 
    describe_parameters([], ParameterFilters, 
                        MaxResults, NextToken, AwsConfig).

-spec describe_parameters(Filters :: [],
                          ParameterFilters :: [],
                          MaxResults :: 1..50, 
                          NextToken :: string(), 
                          AwsConfig :: aws_config())  -> {ok, parameters_list(), next_token_out()} | {error, term()}| no_return().
describe_parameters(Filters, ParameterFilters, MaxResults, 
                    NextToken, #aws_config{}=AwsConfig) 
                when is_list(Filters) andalso
                     is_list(ParameterFilters) andalso
                     is_integer(MaxResults) andalso
                     MaxResults >= 1 andalso 
                     MaxResults =< 50 andalso
                     is_list(NextToken) -> 
                                    
    JsonRequest = maybe_add_field(<<"Filters">>, Filters, []) ++ 
                  maybe_add_field(<<"ParameterFilters">>, ParameterFilters, []) ++
                  maybe_add_field(<<"NextToken">>, NextToken, "") ++ 
                  [{<<"MaxResults">>, MaxResults}],

    case request(AwsConfig, "AmazonSSM.DescribeParameters", JsonRequest) of 
        {ok, Response} -> 
            Parameters = erlcloud_util:kvget(Response, <<"Parameters">>, []),
            NextToken  = erlcloud_util:kvget(Response, <<"NextToken">>),
            {ok, Parameters, NextToken};
        {error, Reason}=Err -> 
            Err
    end.

-spec parameter_filter(Key :: parameter_filter_key() , 
                       Values :: [string()|_])
                    -> parameter_filter_ret().
parameter_filter(Key, [_|_]=Values) -> 
    [{<<<<"Key">>/binary>>, to_parameter_filter_key_string(Key)},
     {<<<<"Values">>/binary>>, Values}].

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
-spec to_parameter_filter_key_string(parameter_filter_key()) -> binary().
to_parameter_filter_key_string(name) -> 
    <<<<"Name">>/binary>>;
to_parameter_filter_key_string(type) -> 
    <<<<"Type">>/binary>>;
to_parameter_filter_key_string(key_id) -> 
    <<<<"KeyId">>/binary>>.

-spec maybe_add_field(Name :: binary(), ExcludeIfEqual, ExcludeIfEqual) -> [].
maybe_add_field(_Name, ExcludeIfEqual, ExcludeIfEqual) -> 
    [];
maybe_add_field(Name, Data, _ExcludeIfEqual) -> 
    [{Name, Data}].

-spec request(Config :: aws_config(),
              Operation :: string(),
              Json :: jsx:json_term())
             -> {ok, jsx:term()} | {error, term()}| no_return().
request(Config0 , Operation, Json) ->
    Body = jsx:encode(Json),
    Host = get_ssm_host(Config0),
    Scheme = get_ssm_scheme(Config0),
    Port = get_ssm_port(Config0),
    
    Url = Scheme ++ Host ++ ":" ++ integer_to_list(Port),
    case erlcloud_aws:update_config(Config0) of
        {ok, Config} ->
            Headers = headers(Host, Config, Operation, Body),
            do_request(Url, Config, Headers, Body);
        {error, Reason} ->            
            {error, Reason}
    end.

-spec do_request(Url :: string(), Config :: aws_config(),
                 Headers :: proplists:proplist(),
                 Body :: binary()) ->  {ok, jsx:term()} | no_return().
do_request(Url, Config, Headers, Body) ->
    case erlcloud_httpc:request(Url, post,
        [{<<"content-type">>, <<"application/x-amz-json-1.1">>} | Headers],
        Body, 5000, Config) of
        {ok, {{200, _}, _, RespBody}} ->
            %% TODO check crc
            {ok, jsx:decode(RespBody)};
        Error ->
            error({"Aws error", Error})
    end.

-spec headers(string(), aws_config(), string(), binary()) -> any().
headers(Host, Config, Operation, Body) ->
    Headers = [{"host", Host},
               {"x-amz-target", Operation}],

    erlcloud_aws:sign_v4_headers(Config, Headers, Body, erlcloud_aws:aws_region_from_host(Host), "ssm").

-spec get_ssm_host(AwsConfig :: aws_config()) -> string().
get_ssm_host(AwsConfig) ->
    AwsConfig#aws_config.ssm_host.

-spec get_ssm_scheme(AwsConfig :: aws_config()) -> string().
get_ssm_scheme(AwsConfig) ->
    AwsConfig#aws_config.ssm_scheme.

-spec get_ssm_port(AwsConfig :: aws_config()) -> pos_integer().
get_ssm_port(AwsConfig) ->
    AwsConfig#aws_config.ssm_port.
