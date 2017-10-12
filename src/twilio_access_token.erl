%%%-------------------------------------------------------------------
%%% @doc This module generates JSON-JWT Twilio Access Tokens.
%%% This is based on the github twilio/twilio-python library version 6.7.1 code.
%%% Still a bare-bones implementation for development purposes.
%%%
%%% @end
%%%-------------------------------------------------------------------

-module(twilio_access_token).

-export([create_token/5,
         create_token/6,
         to_jwt/1]).

-include("twilio.hrl").

-define(DEFAULT_EXPIRATION, 3600).
-define(DEFAULT_ALGORITHM, "HS256").

-spec create_token(AccountSID   :: binary(),
                   ApiKeySid    :: binary(),
                   ApiKeySecret :: binary(),
                   Identity     :: binary(),
                   Grants       :: binary())
                  -> list().

create_token(AccountSID, ApiKeySid, ApiKeySecret, Identity, Grants) ->
    create_token(AccountSID, ApiKeySid, ApiKeySecret, Identity, Grants, <<"">>).

-spec create_token(AccountSID   :: binary(),
                   ApiKeySid    :: binary(),
                   ApiKeySecret :: binary(),
                   Identity     :: binary(),
                   Grants       :: binary(),
                   ConfigurationProfileSID :: binary())
                  -> list().

create_token(AccountSID, ApiKeySid, ApiKeySecret, Identity, Grants, ConfigurationProfileSID) ->
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
     | case ConfigurationProfileSID of
           <<>> -> [];
           undefined -> [];
           _ -> [{configuration_profile_sid, ConfigurationProfileSID}]
       end].

-spec get_value(Key :: atom(), Token :: list()) -> any().

get_value(Key, Token) ->
    proplists:get_value(Key, Token).

algorithm(Token) ->
    get_value(algorithm, Token).
configuration_profile_sid(Token) ->
    get_value(configuration_profile_sid, Token).
identity(Token) ->
    get_value(identity, Token).
secret_key(Token) ->
    get_value(secret_key, Token).
signing_key_sid(Token) ->
    get_value(api_key_sid, Token).
subject(Token) ->
    get_value(subject, Token).
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

grants_with_identity(Token) ->
    [{identity, identity(Token)}
     | pack_grants(grants(Token))] ++
        case configuration_profile_sid(Token) of
            undefined -> [];
            <<>> -> [];
            CPS -> [{configuration_profile_sid, CPS}]
        end.

jti(Token, Now) ->
    Sid = signing_key_sid(Token),
    TimeBin = erlang:integer_to_binary(Now),
    <<Sid/binary, "-", TimeBin/binary>>.

generate_headers(_) ->
    [{<<"cty">>, <<"twilio-fpa;v=1">>}].

-spec generate_payload(any()) -> list(claim()).

generate_payload(Token) ->
    Now = twilio_util:system_time(),
    Sid = signing_key_sid(Token),
    [
     {jti, jti(Token, Now)},
     {iss, Sid},
     {sub, subject(Token)},
     {exp, Now + ttl(Token)},
     {grants, grants_with_identity(Token)}
     ].

-spec to_jwt(any()) -> binary().

to_jwt(Token) ->
    Payload = generate_payload(Token),
    SecretKey = secret_key(Token),
    Algorithm = algorithm(Token),
    Header = generate_headers(Token),
    twilio_jsonjwt:encode(Payload, SecretKey,Algorithm, Header).

%%------------------------------------------------------------------------------
%% Unit tests

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

eunit_start() ->
    meck:new(twilio_util, [unstick, passthrough]),
    meck:expect(twilio_util, system_time, fun() -> 1478655570 end).

eunit_stop(_) ->
    meck:unload(twilio_util).

create_token_test_() ->
    [{"Creating tokens",
      {setup, fun eunit_start/0, fun eunit_stop/1,
       fun() ->
               AccountSID = <<"TESTACCOUNTSID">>,
               ApiKeySid = <<"TESTAPIKEYSID">>,
               ApiKeySecret = <<"TESTAPIKEYSECRET">>,
               ConfigurationProfileSID = <<"TESTCONFIGURATIONPROFILESID">>,
               Identity = "example-user",
               Grant = [{key, video}, {value, [{configuration_profile_sid, ConfigurationProfileSID}]}],
               Token = twilio_access_token:create_token(AccountSID, ApiKeySid, ApiKeySecret, Identity, [Grant]),
               Expected =
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
               ?assertEqual(Expected, Token)
       end}},

     {"",
      {setup, fun eunit_start/0, fun eunit_stop/1,
       fun() ->
               AccountSID = <<"TESTACCOUNTSID">>,
               ApiKeySid = <<"TESTAPIKEYSID">>,
               ApiKeySecret = <<"TESTAPIKEYSECRET">>,
               ConfigurationProfileSID = <<"TESTCONFIGURATIONPROFILESID">>,
               Identity = <<"example-user">>,
               Grant = [{key, video}, {value, [{configuration_profile_sid, ConfigurationProfileSID}]}],

               Token = twilio_access_token:create_token(AccountSID, ApiKeySid, ApiKeySecret, Identity, [Grant]),
               Jwt = twilio_access_token:to_jwt(Token),
               Expected = <<"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiIsImN0eSI6InR3aWxpby1mcGE7dj0xIn0=.eyJqdGkiOiJURVNUQVBJS0VZU0lELTE0Nzg2NTU1NzAiLCJpc3MiOiJURVNUQVBJS0VZU0lEIiwic3ViIjoiVEVTVEFDQ09VTlRTSUQiLCJleHAiOjE0Nzg2NTkxNzAsImdyYW50cyI6eyJpZGVudGl0eSI6ImV4YW1wbGUtdXNlciIsInZpZGVvIjp7ImNvbmZpZ3VyYXRpb25fcHJvZmlsZV9zaWQiOiJURVNUQ09ORklHVVJBVElPTlBST0ZJTEVTSUQifX19.sXsUQPo9USIDlgeDnvcE9IJ+WGVhJvqwWU6kX7FMNDM=">>,

               ?assertEqual(Expected, Jwt)
       end}}].

-endif.

%%------------------------------------------------------------------------------
