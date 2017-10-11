%%%-------------------------------------------------------------------
%%% @doc This module generates JSON-JWT Twilio Access Tokens.
%%% This is based on the github twilio/twilio-python library version 6.7.1 code.
%%% Still a bare-bones implementation for development purposes.
%%%
%%% @end
%%%-------------------------------------------------------------------

-module(twilio_access_token).

-export([create_token/5,
         to_jwt/1]).

-define(DEFAULT_EXPIRATION, 3600).
-define(DEFAULT_ALGORITHM, "HS256").

-spec create_token(AccountSID   :: binary(),
                   ApiKeySid    :: binary(),
                   ApiKeySecret :: binary(),
                   Identity     :: binary(),
                   Grants       :: binary())
                  -> list().

create_token(AccountSID, ApiKeySid, ApiKeySecret, Identity, Grants) ->
    [{account_sid, AccountSID},
     {api_key_sid, ApiKeySid},
     {api_key_secret, ApiKeySecret},
     {identity, Identity},
     {grants, Grants},

     {secret_key, ApiKeySecret},
     {algorithm, ?DEFAULT_ALGORITHM},
     {issuer, ApiKeySid},
     {subject, AccountSID},
     %% {nbf, Jwt.GENERATE},
     {ttl, ?DEFAULT_EXPIRATION}
     %% valid_until=None
    ].

-spec get_value(Key :: atom(), Token :: map()) -> any();
	       (Key :: atom(), Token :: list()) -> any().

get_value(Key, Token) when is_map(Token) ->
    maps:get(Key, Token);
get_value(Key, Token) ->
    proplists:get_value(Key, Token).

algorithm(Token) ->
    get_value(algorithm, Token).
identity(Token) ->
    get_value(identity, Token).
secret_key(Token) ->
    get_value(secret_key, Token).
signing_key_sid(Token) ->
    get_value(api_key_sid, Token).
ttl(Token) ->
    get_value(ttl, Token).

grant_key(Grant) ->
    get_value(key, Grant).

grant_payload(Grant) ->
    get_value(value, Grant).

grants(Token) ->
    get_value(grants, Token).

pack_grants([]) ->
    [];
pack_grants([H | T]) ->
    [{grant_key(H), grant_payload(H)} | pack_grants(T)].

grants_with_identity(Token) when is_map(Token) ->
    maps:put(identity,
             identity(Token),
             grants(grants(Token)));
grants_with_identity(Token) ->
    [{identity, identity(Token)} | pack_grants(grants(Token))].

jti(Token, Now) ->
  io_lib:format("~s-~p", [signing_key_sid(Token), Now]).

payload(Token) when is_map(Token) ->
    Now = twilio_util:system_time(),
    Payload = #{
      jti => jti(Token, Now),
      grants => grants_with_identity(Token)
     },

    Payload;
payload(Token) ->
    Now = twilio_util:system_time(),
    [
     {scope, <<"">>},  %% TODO: proper scope here
     {iss, signing_key_sid(Token)},
     {exp, Now + ttl(Token)},
     {grants, pack_grants(grants(Token))}
     ].

to_jwt(Token) ->
    Payload = payload(Token),
    twilio_jsonjwt:encode(Payload, secret_key(Token), algorithm(Token)).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

create_token_test_() ->
    [{"Creating tokens",
      fun() ->
              AccountSID = <<"TESTACCOUNTSID">>,
              ApiKeySid = <<"TESTAPIKEYSID">>,
              ApiKeySecret = <<"TESTAPIKEYSECRET">>,
              ConfigurationProfileSID = <<"TESTCONFIGURATIONPROFILESID">>,
              Identity = "example-user",
              Grant = [{key, video}, {value, [{configuration_profile_sid, ConfigurationProfileSID}]}],
              Token = twilio_access_token:create_token(AccountSID, ApiKeySid, ApiKeySecret, Identity, [Grant]),

              ?assertEqual(
                 [{account_sid,<<"TESTACCOUNTSID">>},
                  {api_key_sid,<<"TESTAPIKEYSID">>},
                  {api_key_secret,<<"TESTAPIKEYSECRET">>},
                  {identity,"example-user"},
                  {grants,
                   [[{key,video},
                     {value,
                      [{configuration_profile_sid,
                        <<"TESTCONFIGURATIONPROFILESID">>}]}]]},
                  {secret_key,<<"TESTAPIKEYSECRET">>},
                  {algorithm,"HS256"},
                  {issuer,<<"TESTAPIKEYSID">>},
                  {subject,<<"TESTACCOUNTSID">>},
                  {ttl,3600}],
                 Token)
      end},
     {"",
      fun() ->
              meck:new(twilio_util, [unstick, passthrough]),
              meck:expect(twilio_util, system_time, fun() -> 0 end),
              AccountSID = <<"TESTACCOUNTSID">>,
              ApiKeySid = <<"TESTAPIKEYSID">>,
              ApiKeySecret = <<"TESTAPIKEYSECRET">>,
              ConfigurationProfileSID = <<"TESTCONFIGURATIONPROFILESID">>,
              Identity = "example-user",
              Grant = [{key, video}, {value, [{configuration_profile_sid, ConfigurationProfileSID}]}],
              Token = twilio_access_token:create_token(AccountSID, ApiKeySid, ApiKeySecret, Identity, [Grant]),
              Jwt = twilio_access_token:to_jwt(Token),
              ?assertEqual(
                 <<"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzY29wZSI6IiIsImlzcyI6IlRFU1RBUElLRVlTSUQiLCJleHAiOjM2MDAsImdyYW50cyI6eyJ2aWRlbyI6eyJjb25maWd1cmF0aW9uX3Byb2ZpbGVfc2lkIjoiVEVTVENPTkZJR1VSQVRJT05QUk9GSUxFU0lEIn19fQ==.AMElNPqvM2qdnHbNoMkUD+U2mmg9jkNUZK1xGbRiHNM=">>,
                 Jwt),
              meck:unload(twilio_util)
      end}
    ].
-endif.

